# Project_3_KoiStealer_C2_Analysis

This repository documents a security incident analysis of a confirmed Koi Stealer malware infection. The project serves as a practical exercise in network forensics, using open-source tools and custom scripts to identify and investigate Command and Control (C2) communication.

## Project Overview

The primary goal was to act as a security analyst, starting with a PCAP file containing suspicious network activity. Through a structured, step-by-step process, we were able to:

1.  **Triage** the network traffic to identify top talkers and suspicious protocols.
2.  **Analyze** DNS and HTTP traffic to pinpoint malicious connections.
3.  **Correlate** observed traffic patterns with known threat intelligence.
4.  **Extract** file artifacts from the network stream to confirm the malicious activity.
5.  **Document** all findings in a formal incident report.

## Source PCAP

The PCAP file analyzed in this project was sourced from [Malware-Traffic-Analysis.net](https://malware-traffic-analysis.net/2024/09/04/index.html). The file corresponds to the traffic analysis exercise for **2024-09-04**.

## Key Findings & Indicators of Compromise (IOCs)

* **Malware Family:** Koi Stealer
* **Compromised Host:** `172.17.0[.]99`
* **Malicious IP Addresses:** `79.124.78[.]197` and `23.220.251[.]149`
* **Command & Control URI:** `/foots.php`
* **File Artifacts Extracted:**
    * `foots.php` (An empty file, artifact of C2 beaconing)
    * `connecttest.txt` (Network connectivity check file)
    * `ProcessMAU.txt` (Reconnaissance file listing processes)
* **Observed Behavior:**
    * Direct IP-based communication to avoid DNS-level detection.
    * HTTP POST beaconing to the C2 server.
    * Attempts at lateral movement via SMB and Kerberos attacks against an internal domain controller.

## Tools Used

* **tshark:** The command-line version of Wireshark, used for filtering and extracting specific traffic details.
* **Python Scripts:** A set of custom scripts designed for automated triage, DNS, and HTTP analysis.
* **Open-Source Intelligence (OSINT):** Services like AbuseIPDB and VirusTotal were used to check the reputation of IPs and file hashes.

## How to Replicate This Analysis

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/Project_3_KoiStealer_C2_Analysis.git](https://github.com/your-username/Project_3_KoiStealer_C2_Analysis.git)
    cd Project_3_KoiStealer_C2_Analysis
    ```
2.  **Download the PCAP:**
    Download the PCAP from the source link above and place it in the `pcaps/` directory.
3.  **Run the analysis scripts:**
    *(Ensure you have `tshark` and Python 3 installed)*
    ```bash
    python3 scripts/pcap_triage.py pcaps/2024-09-04-traffic-analysis-exercise.pcap
    python3 scripts/dns_agent.py pcaps/2024-09-04-traffic-analysis-exercise.pcap
    python3 scripts/http_agent.py pcaps/2024-09-04-traffic-analysis-exercise.pcap
    ```
4.  **Extract Files:**
    Use `tshark` to export files from the HTTP stream.
    ```bash
    tshark -r pcaps/2024-09-04-traffic-analysis-exercise.pcap --export-objects http,./extracted_files
    ```
5.  **Analyze Hashes:**
    Calculate the SHA256 hashes of the extracted files and check them on VirusTotal to confirm their status.
    ```bash
    sha256sum extracted_files/foots.php
    ```
    

---
*Disclaimer: The IPs and domains in this project have been defanged by replacing periods with `[.]` to prevent accidental clicks or security issues. Always exercise caution when handling malicious artifacts.*
