import nmap
import subprocess
import re
import sys
import time
import requests
import socket  # Added for DNS resolution
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet


def install_packages():
    try:
        print("Installing required packages...")
        print("Updating")
        subprocess.run(["sudo", "apt", "update"])
        print("Installing Nmap ...")
        subprocess.run(["sudo", "apt", "install", "nmap", "-y"])
        print("Installing Searchsploit ...")
        subprocess.run(["sudo", "apt", "install", "exploitdb", "-y"])
        print("Packages installed successfully.")
    except Exception as e:
        print("Error installing packages:", e)
        sys.exit(1)


def nmap_scan(ip_address):
    print("Starting network scan ...")
    scanner = nmap.PortScanner()
    scanner.scan(ip_address, arguments='-sV')

    service_versions = {}
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto]:
                service = scanner[host][proto][port]
                if 'product' in service and 'version' in service:
                    service_name = service['product']
                    service_version = service['version']
                    service_versions[port] = {'service': service_name, 'version': service_version}

    return service_versions

def search_exploitdb(service_versions):
    print("Looking for known exploits ...")
    exploits = []
    for port, info in service_versions.items():
        query = f"{info['service']} {info['version']} exploit"
        command = ["searchsploit", "-w", query]
        try:
            output = subprocess.check_output(command, universal_newlines=True)
            lines = output.strip().split('\n')
            for line in lines:
                # Remove ANSI escape codes from the line
                line = re.sub(r'\x1b\[[0-9;]*m', '', line)
                parts = re.split(r'\s{2,}\|?\s{2,}', line.strip(), maxsplit=1)
                if len(parts) >= 2:
                    exploit_info = {
                        'title': parts[0].strip(),
                        'path': parts[1].strip()
                    }
                    exploits.append(exploit_info)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"Error executing searchsploit: {e}")

    return exploits

def directory_enumeration(ip_address):
    print("Starting directory enumeration ...")
    directories = []
    wordlist_file = "directories.txt"
    with open(wordlist_file, 'r') as f:
        for line in f:
            directory = line.strip()
            url = f"http://{ip_address}/{directory}"
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    directories.append(url)
            except requests.RequestException as e:
                print(f"Error accessing {url}: {e}")
    
    return directories

def subdomain_enumeration(domain):
    print("Starting subdomain enumeration ...")
    subdomains = []
    wordlist_file = "subdomains.txt"  
    with open(wordlist_file, 'r') as f:
        for line in f:
            subdomain = line.strip()
            full_domain = f"{subdomain}.{domain}"
            try:
                ip_address = socket.gethostbyname(full_domain)
                subdomains.append((full_domain, ip_address))
            except socket.error:
                pass  
    
    return subdomains

def generate_pdf_report(ip_address, service_versions, exploits, directories, subdomains):
    print("Generating the report ...")
    formatted_time = time.strftime("%d_%m_%y_%H:%M:%S", time.localtime())
    doc = SimpleDocTemplate(f"report_{ip_address}_{formatted_time}.pdf", pagesize=letter)
    report_content = []

    report_content.append(Paragraph(f"Scan Report for {ip_address}", getSampleStyleSheet()['Title']))
    report_content.append(Spacer(1, 12))

    service_data = [['Port', 'Service', 'Version']]
    for port, info in service_versions.items():
        service_data.append([port, info['service'], info['version']])
    service_table = Table(service_data, repeatRows=1)
    service_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                                       ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                                       ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                                       ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                                       ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                                       ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                                       ('GRID', (0, 0), (-1, -1), 1, colors.black)]))
    report_content.append(Paragraph("Service Versions:", getSampleStyleSheet()['Heading2']))
    report_content.append(service_table)
    report_content.append(Spacer(1, 12))

    exploit_data = [['Exploit Title', 'Link']]
    for exploit in exploits:
        exploit_title = re.sub(r'\x1b\[[0-9;]*[mK]', '', exploit['title'])
        exploit_path = re.sub(r'\x1b\[[0-9;]*[mK]', '', exploit['path'])
        exploit_url = next((part for part in exploit_path.split() if part.startswith("http://") or part.startswith("https://")), "URL")
        exploit_data.append([Paragraph(exploit_title, getSampleStyleSheet()['BodyText']), exploit_url])
    exploit_table = Table(exploit_data, repeatRows=1)
    exploit_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                                       ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                                       ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                                       ('FONTNAME', (0, 0), (-1, 0), 'Helvetica'),
                                       ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                                       ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                                       ('GRID', (0, 0), (-1, -1), 1, colors.black)]))
    report_content.append(Paragraph("Exploits:", getSampleStyleSheet()['Heading2']))
    report_content.append(exploit_table)

    if directories:
        report_content.append(Spacer(1, 12))
        report_content.append(Paragraph("Directories Found:", getSampleStyleSheet()['Heading2']))
        for directory in directories:
            report_content.append(Paragraph(directory, getSampleStyleSheet()['BodyText']))

    if subdomains:
        report_content.append(Spacer(1, 12))
        report_content.append(Paragraph("Subdomains Found:", getSampleStyleSheet()['Heading2']))
        for subdomain, ip_address in subdomains:
            subdomain_info = f"Subdomain: {subdomain}, IP: {ip_address}"
            report_content.append(Paragraph(subdomain_info, getSampleStyleSheet()['BodyText']))

    doc.build(report_content)


def main():
    ip_address = input("Enter IP address: ")
    run_nmap = input("Do you want to run Nmap? (yes/no): ").lower()
    run_searchsploit = input("Do you want to run Searchsploit? (yes/no): ").lower()
    run_directory_enum = input("Do you want to run directory enumeration? (yes/no): ").lower()
    run_subdomain_enum = input("Do you want to run subdomain enumeration? (yes/no): ").lower()

    versions = {}
    exploits = []
    directories = []
    subdomains = []

    if run_nmap == 'yes':
        versions = nmap_scan(ip_address)

    if run_searchsploit == 'yes' and versions:
        exploits = search_exploitdb(versions)

    if run_directory_enum == 'yes':
        directories = directory_enumeration(ip_address)

    if run_subdomain_enum == 'yes':
        domain = ".".join(ip_address.split('.')[1:])
        subdomains = subdomain_enumeration(domain)

    if versions or exploits or directories or subdomains:
        generate_pdf_report(ip_address, versions, exploits, directories, subdomains)
        print("\nPDF report generated successfully.")
    else:
        print("No data to generate report.")

if __name__ == "__main__":
    main()