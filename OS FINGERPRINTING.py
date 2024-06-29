import argparse
import nmap
import csv
import os
import sys


def scan_host(ip, ports):
    nm = nmap.PortScanner()
    nm.scan(ip, ports)
    host_info = nm[ip]
    
    for proto in nm[ip].all_protocols():
        lport = nm[ip][proto].keys()
        for port in lport:
            host_info = {
                'ip': ip,
                'os': nm[ip].get('osclass', {}).get('osfamily', 'unknown'),
                'port': port,
                "name": nm[ip][proto][port].get('name', 'unknown'),
                'product': nm[ip][proto][port].get('product', 'unknown'),
                'version': nm[ip][proto][port].get('version', 'unknown'),
            }
            host_info.append(host_info)
            
            
        return host_info
    
    
def output_to_csv(output_file,host_info):
    fieldnames = ['ip', 'os', 'port', 'name', 'product', 'version']
    file_exists = os.path.isfile(output_file)
    
    with open(output_file, 'a') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        if not file_exists:
            writer.writeheader()
            
        writer.writerow(host_info)
        
        
    def main():
        parser = argparse.ArgumentParser(description='Scan a single hostfor open ports and services')
        parser.add_argument('ip', help='IP address of the host to scan')
        parser.add_argument('ports', help='Ports to scan')      
        parser.add_argument('output_file', help='File to write output to')
        args = parser.parse_args()
        
        ip = args.host
        ports = args.ports
        output_file = args.output_file
        
        print(f"Scanning IP : {ip}")
        print(f"Ports : {ports}")
        
        sys.stdout.write("Scanning...")
        sys.stdout.flush()
        
        host_infos = scan_host(ip, ports)
        
        
        for host_info in host_infos:
            output_to_csv(output_file, host_info)
            
        print("\n\nScan complete")
        for host_info in host_infos:
            print(f"Host: {host_info['ip']}")
            print(f"OS: {host_info['os']}")
            print(f"Port: {host_info['port']}")
            print(f"Name: {host_info['name']}")
            print(f"Product: {host_info['product']}")
            print(f"Version: {host_info['version']}")
            
        if __name__ == '__main__':
            main()
        