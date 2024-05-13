# Cybersecurity Assessment Tool

## Overview
OneForAll Tool is a Python script designed to assist in security assessments of networked systems. It integrates various tools such as Nmap for port scanning, Searchsploit for exploit searching, and custom directory and subdomain enumeration. The tool generates detailed PDF reports summarizing the findings of the assessment.

## Requirements
- Python 3.x
- Nmap
- Searchsploit
- Wordlist files for directory and subdomain enumeration

## Installation
1. Clone the repository: `git clone https://github.com/yourusername/cybersecurity-assessment-tool.git`
2. Install Python dependencies: `pip3 install -r requirements.txt`
3. Install Nmap and Searchsploit if not already installed.

## Usage
1. Navigate to the directory containing the script.
2. Run the script: `python main.py`
3. Follow the prompts:
   - Enter the target IP address when prompted.
   - Choose whether to run Nmap for port scanning.
   - Choose whether to search for exploits using Searchsploit.
   - Choose whether to perform directory enumeration.
   - Choose whether to perform subdomain enumeration.
4. Review the generated PDF report in the same directory.

## Syntax Explanation
- The script takes the target IP address as input.
- Users are prompted to select which modules to run:
  - Nmap: Performs port scanning to identify open ports and services.
  - Searchsploit: Searches for exploits related to identified services and versions.
  - Directory Enumeration: Scans for accessible directories on the target web server.
  - Subdomain Enumeration: Searches for subdomains associated with the target domain.
- The tool generates a PDF report summarizing the findings of the assessment.


