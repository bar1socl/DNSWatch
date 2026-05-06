import sys
import os
import csv
import subprocess
from itertools import zip_longest

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

def run_tshark(pcap_file):
    """
    Executes Tshark to parse DNS packets from the given PCAP/PCAPNG file.
    Returns a subprocess.Popen object if successful, None otherwise.
    """
    cmd = [
        TSHARK_PATH,
        "-r", pcap_file,
        "-Y", "dns",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "dns.flags.response",
        "-e", "dns.qry.name",
        "-e", "dns.qry.type",
        "-e", "dns.flags.rcode",
        "-e", "dns.resp.name",
        "-e", "dns.resp.type",
        "-e", "dns.resp.ttl",
        "-e", "dns.a",
        "-e", "dns.aaaa",
        "-e", "dns.cname",
        "-E", "header=n",
        "-E", "separator=/t",
        "-E", "quote=n",
        "-E", "occurrence=a",
        "-E", "aggregator=,"
    ]
    
    try:
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            universal_newlines=True,
            encoding='utf-8',
            errors='replace'
        )
        return process
    except FileNotFoundError:
        return None

def process_tshark_output(process, output_csv):
    """
    Reads Tshark stdout line by line, unpacks multiple answers correctly,
    and writes the structured data to a CSV file.
    """
    total_records = 0
    with open(output_csv, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp", "src_ip", "dst_ip", "qr", "qname", 
            "qtype", "rcode", "rrname", "rrtype", "rdata", "ttl"
        ])

        for line in process.stdout:
            line = line.strip('\n')
            if not line:
                continue
                
            fields = line.split('\t')
            if len(fields) < 13:
                # Malformed output from tshark, skip it
                print(f"Debug: Skipping malformed row: {line}", file=sys.stderr)
                continue
                
            timestamp = fields[0]
            src_ip = fields[1]
            dst_ip = fields[2]
            qr = fields[3]
            qname = fields[4]
            qtype = fields[5]
            rcode = fields[6]
            
            rrname_str = fields[7]
            rrtype_str = fields[8]
            ttl_str = fields[9]
            a_str = fields[10]
            aaaa_str = fields[11]
            cname_str = fields[12]
            
            # Use the most inner IP address if multiple encap layers
            if ',' in src_ip: src_ip = src_ip.split(',')[-1]
            if ',' in dst_ip: dst_ip = dst_ip.split(',')[-1]
            
            # Default to first query if multiple exist
            if ',' in qr: qr = qr.split(',')[0]
            if ',' in qname: qname = qname.split(',')[0]
            if ',' in qtype: qtype = qtype.split(',')[0]
            if ',' in rcode: rcode = rcode.split(',')[0]

            rrnames = rrname_str.split(',') if rrname_str else []
            rrtypes = rrtype_str.split(',') if rrtype_str else []
            ttls = ttl_str.split(',') if ttl_str else []
            
            a_records = [x for x in a_str.split(',') if x]
            aaaa_records = [x for x in aaaa_str.split(',') if x]
            cname_records = [x for x in cname_str.split(',') if x]
            
            if not rrnames:
                writer.writerow([timestamp, src_ip, dst_ip, qr, qname, qtype, rcode, '', '', '', ''])
                total_records += 1
                continue
                
            for r_name, r_type, r_ttl in zip_longest(rrnames, rrtypes, ttls, fillvalue=''):
                if r_name == '':
                    continue
                
                r_data = ''
                if r_type == '1' and a_records:
                    r_data = a_records.pop(0)
                elif r_type == '28' and aaaa_records:
                    r_data = aaaa_records.pop(0)
                elif r_type == '5' and cname_records:
                    r_data = cname_records.pop(0)
                
                writer.writerow([
                    timestamp, src_ip, dst_ip, qr, qname, 
                    qtype, rcode, r_name, r_type, r_data, r_ttl
                ])
                total_records += 1
                
        # Wait for the process to complete gracefully
        _, err_output = process.communicate()
        
        if process.returncode != 0:
            print(f"Error: tshark exited with code {process.returncode}", file=sys.stderr)
            if err_output:
                print(err_output.strip(), file=sys.stderr)
            sys.exit(1)
        
    return total_records

def main():
    print("DNSWatch started")
    
    if len(sys.argv) < 2:
        print("Error: No PCAP/PCAPNG file provided.")
        print("Usage: python src/main.py <pcap_file>")
        sys.exit(1)
        
    pcap_file = sys.argv[1]
    
    if not os.path.isfile(pcap_file):
        print("Error: File does not exist.")
        sys.exit(1)
        
    print("File validated")
    print("Processing started")
    
    outputs_dir = "outputs"
    os.makedirs(outputs_dir, exist_ok=True)
    
    basename = os.path.splitext(os.path.basename(pcap_file))[0]
    output_csv = os.path.join(outputs_dir, f"dns_events_{basename}.csv")
    
    process = run_tshark(pcap_file)
    if not process:
        print("Error: Tshark not found. Ensure it is installed at the expected path.")
        sys.exit(1)
        
    total_records = process_tshark_output(process, output_csv)
    
    if total_records == 0:
        print("Warning: 0 DNS records found. The capture may contain no DNS traffic or be empty.", file=sys.stderr)
    else:
        print(f"Total DNS records written: {total_records}")
        
    print(f"Output file path: {output_csv.replace(os.sep, '/')}")

if __name__ == "__main__":
    main()
