# Explanation:
WebVulnScan is a Python-based tool designed for conducting vulnerability assessments on web applications using the powerful capabilities of Nmap. It provides two primary scanning options to cater to different needs: stealthy and aggressive scans.

# Features:
+ Stealth Scan: This mode employs stealth techniques to minimize detection by security mechanisms such as firewalls and intrusion detection systems. It uses TCP SYN scanning (-sS) with a slow timing template (-T2) to reduce the likelihood of being noticed.
+ Aggressive Scan: In this mode, WebVulnScan utilizes all available techniques to perform a comprehensive assessment, even if it takes a considerable amount of time. It uses the -A option for aggressive scanning, combined with a faster timing template (-T4), enabling OS detection, version detection, script scanning, and traceroute.

# Usage:
+ Input: The user is prompted to enter the URL or IP address of the web application they wish to scan.
+ Selection: The user chooses between a stealth scan and an aggressive scan, depending on their requirements.
+ Execution: The tool runs the selected scan using Nmap and displays the results in the console

# Disclaimer:
WebVulnScan should only be used with explicit permission to scan web applications, as unauthorized scanning can be illegal and against ethical guidelines. Ensure you comply with all relevant laws and policies before conducting scans.

This tool simplifies the process of identifying potential vulnerabilities in web applications, helping security professionals and developers to enhance their security posture by providing insights into possible weaknesses.
