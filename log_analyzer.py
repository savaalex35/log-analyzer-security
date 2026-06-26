"""
Log Analyzer for Security
A Python script to analyze server logs for suspicious activity.
Author: Sava Alexandru
"""

import re
from collections import Counter
from datetime import datetime


def extract_ips(log_file):
    """Extract all IP addresses from log file."""
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    
    with open(log_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    ips = re.findall(ip_pattern, content)
    return ips


def count_ip_frequency(ips):
    """Count how many times each IP appears."""
    return Counter(ips)


def detect_brute_force(log_file, threshold=5):
    """
    Detect brute force attacks.
    An IP with 'Failed login' >= threshold times is flagged.
    """
    brute_force_ips = {}
    
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            if 'Failed login' in line:
                ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                if ip_match:
                    ip = ip_match.group()
                    brute_force_ips[ip] = brute_force_ips.get(ip, 0) + 1
    
    # Filter only IPs that exceed threshold
    suspicious = {ip: count for ip, count in brute_force_ips.items() if count >= threshold}
    return suspicious


def generate_report(log_file, output_file):
    """Generate security analysis report."""
    ips = extract_ips(log_file)
    ip_freq = count_ip_frequency(ips)
    brute_force = detect_brute_force(log_file)
    
    report = []
    report.append("=" * 60)
    report.append("SECURITY LOG ANALYSIS REPORT")
    report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("=" * 60)
    report.append("")
    
    # Summary
    report.append(f"Total log entries analyzed: {len(ips)}")
    report.append(f"Unique IP addresses found: {len(ip_freq)}")
    report.append("")
    
    # IP Frequency
    report.append("-" * 60)
    report.append("IP ADDRESS FREQUENCY")
    report.append("-" * 60)
    for ip, count in ip_freq.most_common():
        report.append(f"  {ip:<20} | Appearances: {count}")
    report.append("")
    
    # Brute Force Detection
    report.append("-" * 60)
    report.append("BRUTE FORCE DETECTION (Failed login >= 5 attempts)")
    report.append("-" * 60)
    if brute_force:
        report.append("ALERT: Potential brute force attacks detected!")
        report.append("")
        for ip, count in brute_force.items():
            report.append(f"  THREAT: {ip:<20} | Failed attempts: {count}")
    else:
        report.append("No brute force attacks detected.")
    report.append("")
    
    # Recommendations
    report.append("-" * 60)
    report.append("RECOMMENDATIONS")
    report.append("-" * 60)
    if brute_force:
        report.append("• Block the following IPs at firewall level:")
        for ip in brute_force.keys():
            report.append(f"  - {ip}")
        report.append("• Review authentication policies for affected accounts.")
        report.append("• Consider implementing rate limiting on login endpoints.")
    else:
        report.append("• Continue monitoring for anomalies.")
        report.append("• Review logs periodically for new threats.")
    
    report.append("")
    report.append("=" * 60)
    report.append("END OF REPORT")
    report.append("=" * 60)
    
    # Write report to file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(report))
    
    print(f"Report generated: {output_file}")
    return '\n'.join(report)


def main():
    log_file = 'server_logs.txt'
    output_file = 'security_report.txt'
    
    print("Starting Log Analysis...")
    print(f"Analyzing: {log_file}")
    print("-" * 40)
    
    report = generate_report(log_file, output_file)
    print("\n" + report)


if __name__ == '__main__':
    main()