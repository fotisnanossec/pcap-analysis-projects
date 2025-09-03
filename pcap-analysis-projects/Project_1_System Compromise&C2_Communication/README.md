# Network Traffic Analysis - Incident Analysis 2025-06-13

### Project Overview

This project showcases my skills in network security analysis and incident response. The goal was to analyze a publicly available network traffic capture (PCAP) to identify and document a security incident. This project demonstrates my ability with command-line analysis, my interpretation of findings, and my capacity to produce a clear, structured analysis report.

### Key Findings

My analysis revealed a likely fileless attack originating from an internal host. Key findings include:
* **Initial Access:** The compromise began with the execution of a malicious PowerShell script on the victim host.
* **C2 Communication:** A Command and Control (C2) channel was established over HTTP to multiple domains disguised to look like legitimate services.
* **Data Exfiltration:** Evidence of data exfiltration was found in the C2 traffic, with encoded strings in HTTP URIs.
* **Evasion:** The attack appears to have used a fileless technique to deliver its payload, successfully evading traditional file-based detection methods.

### Methodology and Tools

The analysis was performed using a structured methodology, starting with high-level triage and progressing to a deep-dive investigation.

**PCAP Source:** The PCAP file for this analysis was sourced from the community resource, [Malware-Traffic-Analysis.net](https://malware-traffic-analysis.net/2025/06/13/index.html).

**Tools Used:** This analysis was performed using open-source tools and custom scripts, demonstrating a practical approach to network forensics.
* **TShark:** For high-speed triage and command-line traffic filtering.
* **Python Scripts:** To automate the extraction of key HTTP and DNS data points.
* **Foremost:** For file-carving and malware extraction attempts.

### Final Report and Raw Data

* [**View Full Incident Report**](./reports/Incident_Report_2025-06-13.md)
* **Evidence Files:** The raw JSON and log files from the analysis are available in the `data/findings` directory.
