import sys
import os
import math
import zipfile
import io
from collections import Counter
from datetime import datetime, timezone
from urllib.request import urlopen
from urllib.error import URLError

import pandas as pd  # type: ignore

try:
    import tldextract  # type: ignore
except ImportError:
    print("Error: tldextract is not installed.")
    print("Please run: pip install tldextract")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RECORD_TYPE_MAP = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL",
    12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}

UNUSUAL_TYPES = {16, 10, 255}  # TXT, NULL, ANY

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_TOP_N = 100_000

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    counter = Counter(text)
    length: int = len(text)
    entropy: float = -sum((count / length) * math.log2(count / length)
                          for count in counter.values())
    return round(max(entropy, 0.0), 4)  # type: ignore[call-overload]


def digit_ratio(domain: str) -> float:
    """Calculate the proportion of digit characters, excluding dots."""
    chars: str = domain.replace(".", "")
    if not chars:
        return 0.0
    digits: int = sum(1 for c in chars if c.isdigit())
    return round(digits / len(chars), 4)  # type: ignore[call-overload]


def type_int_to_name(t):
    """Convert a DNS record type integer to a human-readable name."""
    return RECORD_TYPE_MAP.get(t, f"TYPE_{t}")


def get_basename(filename):
    """Derive a short basename from the input CSV filename."""
    base = os.path.basename(filename)
    if base.endswith(".csv"):
        base = base[:-4]
    if base.startswith("dns_events_"):
        base = base[len("dns_events_"):]
    return base


# ---------------------------------------------------------------------------
# Tranco download / load
# ---------------------------------------------------------------------------

def load_tranco(data_dir):
    """
    Load the Tranco top-100K list, downloading it first if necessary.
    Returns a dict mapping domain -> rank, or an empty dict on failure.
    """
    tranco_path = os.path.join(data_dir, "tranco_top100k.csv")

    if not os.path.isfile(tranco_path):
        print("Downloading Tranco top-1M list...")
        try:
            resp = urlopen(TRANCO_URL, timeout=30)
            zip_bytes = io.BytesIO(resp.read())
            with zipfile.ZipFile(zip_bytes) as zf:
                csv_name = zf.namelist()[0]
                with zf.open(csv_name) as f:
                    raw = f.read().decode("utf-8")
        except (URLError, OSError, zipfile.BadZipFile) as e:
            print(f"Warning: Could not download Tranco list ({e}). "
                  "Continuing without Tranco data.")
            return {}

        os.makedirs(data_dir, exist_ok=True)
        lines = raw.strip().splitlines()
        with open(tranco_path, "w", encoding="utf-8", newline="") as out:
            out.write("rank,domain\n")
            for i, line in enumerate(lines):
                if i >= TRANCO_TOP_N:
                    break
                out.write(line + "\n")
        print(f"Saved {TRANCO_TOP_N} entries to {tranco_path}")

    # Load from disk
    tranco = {}
    try:
        with open(tranco_path, encoding="utf-8") as f:
            next(f)  # skip header
            for line in f:
                parts = line.strip().split(",", 1)
                if len(parts) == 2:
                    tranco[parts[1]] = int(parts[0])
    except Exception as e:
        print(f"Warning: Could not read Tranco file ({e}).")
    return tranco


# ---------------------------------------------------------------------------
# Scoring functions
# ---------------------------------------------------------------------------

def score_entropy(entropy_val):
    if entropy_val > 4.0:
        return 30, "high_entropy"
    if entropy_val > 3.5:
        return 20, "moderate_entropy"
    return 0, None


def score_subdomain_entropy(entropy_val, has_subdomain):
    if not has_subdomain:
        return 0, None
    if entropy_val > 4.0:
        return 30, "high_subdomain_entropy"
    if entropy_val > 3.5:
        return 15, "moderate_subdomain_entropy"
    return 0, None


def score_ttl(ttl):
    if pd.isna(ttl):
        return 0, None
    ttl = float(ttl)
    if ttl < 30:
        return 20, "very_low_ttl"
    if ttl < 300:
        return 10, "low_ttl"
    return 0, None


def score_nxdomain_rate(rate):
    if rate > 0.5:
        return 30, "nxdomain_burst"
    if rate > 0.3:
        return 20, "elevated_nxdomain"
    return 0, None


def score_domain_length(length):
    if length > 75:
        return 25, "very_long_domain"
    if length > 50:
        return 15, "long_domain"
    return 0, None


def score_digit_ratio(ratio):
    if ratio > 0.4:
        return 20, "high_digit_ratio"
    if ratio > 0.3:
        return 10, "elevated_digit_ratio"
    return 0, None


def score_unusual_types(type_set):
    if type_set & UNUSUAL_TYPES:
        return 15, "unusual_record_type"
    return 0, None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # --- Argument handling ---------------------------------------------------
    if len(sys.argv) < 2:
        print("Error: No CSV file provided.")
        print("Usage: python src/detect.py <csv_file>")
        sys.exit(1)

    csv_path = sys.argv[1]
    if not os.path.isfile(csv_path):
        print(f"Error: File not found: {csv_path}")
        sys.exit(1)

    # --- Step 1: Load and clean ----------------------------------------------
    df = pd.read_csv(csv_path)
    df = df.dropna(subset=["qname"])
    df = df[df["qname"].astype(str).str.strip() != ""]
    df["ttl"] = pd.to_numeric(df["ttl"], errors="coerce")
    df["rcode"] = pd.to_numeric(df["rcode"], errors="coerce")
    df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")

    if df.empty:
        print("No valid DNS events to analyse.")
        sys.exit(0)

    # --- Step 2: Group by unique qname ---------------------------------------
    def get_mode(series):
        m = series.mode()
        return m.iloc[0] if not m.empty else None

    grouped = df.groupby("qname", as_index=False).agg(
        first_seen_ts=("timestamp", "min"),
        query_count=("timestamp", "count"),
        min_ttl=("ttl", "min"),
        nxdomain_count=("rcode", lambda s: int((s == 3).sum())),  # type: ignore[union-attr]
        src_ip=("src_ip", get_mode),
    )

    grouped["nxdomain_rate"] = round(
        grouped["nxdomain_count"] / grouped["query_count"], 4
    )

    # Convert first_seen timestamp to human-readable string
    grouped["first_seen"] = grouped["first_seen_ts"].apply(
        lambda ts: datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        ) if pd.notna(ts) else ""
    )

    # Collect unique record types per qname (union of qtype and rrtype)
    qtype_sets = (
        df.dropna(subset=["qtype"])
        .groupby("qname")["qtype"]
        .apply(lambda s: set(int(x) for x in s if pd.notna(x)))
    )
    rrtype_sets = (
        df.dropna(subset=["rrtype"])
        .groupby("qname")["rrtype"]
        .apply(lambda s: set(int(x) for x in s if pd.notna(x)))
    )

    type_lookup = {}
    for qname in grouped["qname"]:
        qt = qtype_sets.get(qname, set())
        rt = rrtype_sets.get(qname, set())
        type_lookup[qname] = qt | rt

    grouped["record_type_set"] = grouped["qname"].map(type_lookup)

    # --- Step 3: Extract parent domain with tldextract -----------------------
    def extract_parent(qname):
        ext = tldextract.extract(qname)
        parent = ext.top_domain_under_public_suffix
        return parent if parent else qname

    def extract_subdomain(qname):
        ext = tldextract.extract(qname)
        return ext.subdomain if ext.subdomain else ""

    grouped["parent_domain"] = grouped["qname"].apply(extract_parent)
    grouped["subdomain_part"] = grouped["qname"].apply(extract_subdomain)

    # --- Step 4: Tranco lookup -----------------------------------------------
    data_dir = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "data")
    tranco = load_tranco(data_dir)

    grouped["tranco_rank"] = grouped["parent_domain"].map(tranco)

    # --- Step 5: Feature scoring ---------------------------------------------
    grouped["entropy"] = grouped["qname"].apply(shannon_entropy)
    grouped["subdomain_entropy"] = grouped["subdomain_part"].apply(shannon_entropy)
    grouped["domain_length"] = grouped["qname"].apply(len)
    grouped["digit_ratio_val"] = grouped["qname"].apply(digit_ratio)

    results = []
    for _, row in grouped.iterrows():
        scores_reasons = []

        # Feature 1 — full-domain entropy
        scores_reasons.append(score_entropy(row["entropy"]))
        # Feature 2 — subdomain entropy
        scores_reasons.append(
            score_subdomain_entropy(row["subdomain_entropy"],
                                    bool(row["subdomain_part"]))
        )
        # Feature 3 — TTL
        scores_reasons.append(score_ttl(row["min_ttl"]))
        # Feature 4 — NXDOMAIN rate
        scores_reasons.append(score_nxdomain_rate(row["nxdomain_rate"]))
        # Feature 5 — domain length
        scores_reasons.append(score_domain_length(row["domain_length"]))
        # Feature 6 — digit ratio
        scores_reasons.append(score_digit_ratio(row["digit_ratio_val"]))
        # Feature 7 — unusual record types
        scores_reasons.append(score_unusual_types(row["record_type_set"]))

        feature_scores = [s for s, _ in scores_reasons]
        feature_reasons = [r for _, r in scores_reasons if r is not None]
        features_triggered = sum(1 for s in feature_scores if s > 0)
        raw_score = sum(feature_scores)

        # Step 6 — multi-signal check
        if features_triggered < 2:
            final_score = min(raw_score, 29)
        else:
            if features_triggered >= 3:
                raw_score += 10
            final_score = min(raw_score, 100)

        # Step 7 — category
        tranco_rank = row["tranco_rank"]
        tr_valid = pd.notna(tranco_rank)
        if final_score < 30:
            category = "Safe"
        elif tr_valid:
            category = "Known-Safe"
        elif final_score < 60:
            category = "Suspicious"
        else:
            category = "Dangerous"

        # Step 8 — reasons string
        reasons = "|".join(feature_reasons) if feature_reasons else "none"

        results.append({
            "qname": row["qname"],
            "features_triggered": features_triggered,
            "score": final_score,
            "category": category,
            "reasons": reasons,
        })

    scores_df = pd.DataFrame(results)
    grouped = grouped.merge(scores_df, on="qname", how="left")

    # --- Step 9: Unique subdomain count per parent domain --------------------
    subdomain_counts = (
        grouped.groupby("parent_domain")["qname"]
        .nunique()
        .rename("unique_subdomains")
    )
    grouped = grouped.merge(subdomain_counts, on="parent_domain", how="left")

    # --- Step 10: Build output -----------------------------------------------
    # Record types as pipe-separated names
    grouped["record_types"] = grouped["record_type_set"].apply(
        lambda s: "|".join(sorted(type_int_to_name(t) for t in s)) if s else ""
    )
    grouped["has_unusual_types"] = grouped["record_type_set"].apply(
        lambda s: bool(s & UNUSUAL_TYPES)
    )

    # Rename digit_ratio_val for output
    grouped.rename(columns={"digit_ratio_val": "digit_ratio"}, inplace=True)

    # Format tranco_rank: integer if present, else blank
    grouped["tranco_rank"] = grouped["tranco_rank"].apply(
        lambda x: int(x) if pd.notna(x) else ""
    )

    # Round floats
    for col in ["entropy", "subdomain_entropy", "nxdomain_rate", "digit_ratio"]:
        grouped[col] = grouped[col].round(4)

    # Sort
    grouped.sort_values(
        by=["score", "qname"], ascending=[False, True], inplace=True
    )

    # Final column order
    out_cols = [
        "qname", "parent_domain", "first_seen", "src_ip", "query_count",
        "entropy", "subdomain_entropy", "min_ttl", "nxdomain_rate",
        "domain_length", "digit_ratio", "unique_subdomains", "record_types",
        "has_unusual_types", "tranco_rank", "features_triggered", "score",
        "category", "reasons",
    ]

    out_df = grouped[out_cols].copy()

    # Output paths
    basename = get_basename(csv_path)
    out_dir = "outputs"
    os.makedirs(out_dir, exist_ok=True)
    alerts_file = os.path.join(out_dir, f"alerts_{basename}.csv")
    scored_file = os.path.join(out_dir, f"scored_{basename}.csv")

    alerts_df = out_df[out_df["category"].isin(["Suspicious", "Dangerous"])]
    alerts_df.to_csv(alerts_file, index=False, encoding="utf-8")
    out_df.to_csv(scored_file, index=False, encoding="utf-8")

    # --- Visualisations ------------------------------------------------------
    charts_saved = False
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        # Shared style settings
        cat_colours = {
            "Safe": "#4CAF50",
            "Known-Safe": "#2196F3",
            "Suspicious": "#FF9800",
            "Dangerous": "#F44336",
        }
        PRIMARY = "#2196F3"
        EMPHASIS = "#1565C0"

        # --- Build 2x2 dashboard figure ---------------------------------------
        fig, axes = plt.subplots(2, 2, figsize=(18, 14))
        fig.patch.set_facecolor("white")
        for row in axes:
            for ax in row:
                ax.set_facecolor("white")

        # Summary counts for the header
        counts = out_df["category"].value_counts()
        n_safe = int(counts.get("Safe", 0))
        n_known = int(counts.get("Known-Safe", 0))
        n_susp = int(counts.get("Suspicious", 0))
        n_danger = int(counts.get("Dangerous", 0))
        today_str = datetime.now().strftime("%Y-%m-%d")

        fig.suptitle(
            f"DNSWatch Analysis \u2014 {basename} | Domains: {len(out_df)} | "
            f"Safe: {n_safe} | Known-Safe: {n_known} | Suspicious: {n_susp} | "
            f"Dangerous: {n_danger} | Generated: {today_str}",
            fontsize=13, fontweight="bold",
        )
        fig.subplots_adjust(top=0.92)

        # -- Panel 1: Top Left — Domain Category Distribution ------------------
        ax1 = axes[0, 0]
        cat_order = ["Safe", "Known-Safe", "Suspicious", "Dangerous"]
        cat_counts = out_df["category"].value_counts()
        cat_values = [int(cat_counts.get(c, 0)) for c in cat_order]
        bar_colours = [cat_colours[c] for c in cat_order]

        bars = ax1.bar(cat_order, cat_values, color=bar_colours)
        for bar, val in zip(bars, cat_values):
            ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                     str(val), ha="center", va="bottom", fontsize=11)
        ax1.set_title("Domain Category Distribution", fontsize=13, fontweight="bold")
        ax1.set_xlabel("Category", fontsize=11)
        ax1.set_ylabel("Count", fontsize=11)

        # -- Panel 2: Top Right — Detection Signal Frequency -------------------
        ax2 = axes[0, 1]
        all_reasons = []
        for r in out_df["reasons"]:
            if pd.notna(r) and str(r).strip() and str(r).strip().lower() != "none":
                all_reasons.extend(str(r).split("|"))

        if all_reasons:
            reason_counts = Counter(all_reasons)
            sorted_reasons = sorted(reason_counts.items(), key=lambda x: x[1], reverse=True)
            labels = [item[0] for item in sorted_reasons]
            values = [item[1] for item in sorted_reasons]
            ax2.barh(labels[::-1], values[::-1], color=EMPHASIS)
            ax2.set_xlabel("Number of Domains", fontsize=11)
        else:
            ax2.text(0.5, 0.5, "No detection signals triggered",
                     ha="center", va="center", fontsize=12,
                     transform=ax2.transAxes)
        ax2.set_title("Detection Signal Frequency", fontsize=13, fontweight="bold")

        # -- Panel 3: Bottom Left — Features Triggered Per Domain --------------
        ax3 = axes[1, 0]
        feat_range = list(range(8))  # 0 through 7
        feat_counts = out_df["features_triggered"].value_counts()
        feat_values = [int(feat_counts.get(i, 0)) for i in feat_range]

        bars = ax3.bar([str(i) for i in feat_range], feat_values, color=PRIMARY)
        for bar, val in zip(bars, feat_values):
            ax3.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                     str(val), ha="center", va="bottom", fontsize=11)
        ax3.set_title("Features Triggered Per Domain", fontsize=13, fontweight="bold")
        ax3.set_xlabel("Number of Features Triggered", fontsize=11)
        ax3.set_ylabel("Number of Domains", fontsize=11)

        # -- Panel 4: Bottom Right — Top 10 Most Queried Domains ---------------
        ax4 = axes[1, 1]
        top_domains = out_df.nlargest(10, "query_count")
        domain_names = top_domains["qname"].tolist()[::-1]
        domain_counts = top_domains["query_count"].tolist()[::-1]
        domain_cats = top_domains["category"].tolist()[::-1]
        domain_bar_colours = [cat_colours.get(c, PRIMARY) for c in domain_cats]

        ax4.barh(domain_names, domain_counts, color=domain_bar_colours)
        ax4.set_title("Top 10 Most Queried Domains", fontsize=13, fontweight="bold")
        ax4.set_xlabel("Query Count", fontsize=11)

        # -- Final layout and save ---------------------------------------------
        fig.tight_layout(rect=[0, 0, 1, 0.92])
        dashboard_path = os.path.join(out_dir, f"dashboard_{basename}.png")
        fig.savefig(dashboard_path, dpi=150, bbox_inches="tight")
        plt.close(fig)

        charts_saved = True
        print(f"Dashboard saved to: {dashboard_path}")
    except ImportError:
        print("Warning: matplotlib not installed. Skipping visualisations.")
        print("Install with: pip install matplotlib")
    except Exception as e:
        print(f"Warning: Could not generate dashboard ({e})")

    # --- Console summary -----------------------------------------------------
    counts = out_df["category"].value_counts()
    n_safe = int(counts.get("Safe", 0))
    n_known = int(counts.get("Known-Safe", 0))
    n_susp = int(counts.get("Suspicious", 0))
    n_danger = int(counts.get("Dangerous", 0))

    print("DNSWatch Detection Engine v2.0")
    print(f"Analysing: {os.path.basename(csv_path)}")
    print(f"Domains analysed: {len(out_df)}")
    print(f"  Safe: {n_safe}")
    print(f"  Known-Safe: {n_known}")
    print(f"  Suspicious: {n_susp}")
    print(f"  Dangerous: {n_danger}")
    print(f"Alerts written to: {alerts_file}")
    print(f"Full scores written to: {scored_file}")


if __name__ == "__main__":
    main()
