\# 🔐 Security Log Analyzer



A Python-based tool for analyzing server logs to detect suspicious activity, including brute-force attacks and high-frequency IP appearances.



\## 🎯 Purpose



This project demonstrates practical application of \*\*Python scripting\*\*, \*\*cybersecurity fundamentals\*\*, and \*\*automation\*\* for IT security operations. It was built as part of my transition from Technical Support to Security Operations (SOC Analyst).



\## 🛠️ Features



\- \*\*IP Extraction\*\*: Parses log files and extracts all IP addresses using regex

\- \*\*Frequency Analysis\*\*: Counts how often each IP appears in the logs

\- \*\*Brute-Force Detection\*\*: Identifies IPs with repeated failed login attempts (configurable threshold)

\- \*\*Automated Reporting\*\*: Generates a clean, timestamped security report



\## 📁 Files



| File | Description |

|------|-------------|

| `log\_analyzer.py` | Main Python script |

| `server\_logs.txt` | Sample log file for testing |

| `security\_report.txt` | Generated report (output) |



\## 🚀 How to Run



1\. Clone the repository:

&#x20;  ```bash

&#x20;  git clone https://github.com/savaalex35/log-analyzer-security.git

&#x20;  cd log-analyzer-security

Run the script:

bash

python log\_analyzer.py

Check the generated report:

bash

cat security\_report.txt

📊 Sample Output

plain

============================================================

SECURITY LOG ANALYSIS REPORT

Generated: 2025-01-15 14:30:00

============================================================



Total log entries analyzed: 25

Unique IP addresses found: 5



\------------------------------------------------------------

IP ADDRESS FREQUENCY

\------------------------------------------------------------

&#x20; 203.0.113.50         | Appearances: 9

&#x20; 10.0.0.55            | Appearances: 7



\------------------------------------------------------------

BRUTE FORCE DETECTION (Failed login >= 5 attempts)

\------------------------------------------------------------

ALERT: Potential brute force attacks detected!



&#x20; THREAT: 203.0.113.50  | Failed attempts: 8

&#x20; THREAT: 10.0.0.55     | Failed attempts: 5

🔧 Technologies

Python 3

Regular Expressions (re)

Collections (Counter)

File I/O \& Automation

📚 Background

Built by a Technical Support Specialist (Tier 2) with 5 years of enterprise experience (Verizon via CGS), certified in Google Cybersecurity and Python Programming (IT School).

📬 Contact

LinkedIn: https://www.linkedin.com/in/sava-alexandru-060aa220a/

Email: savaa35@gmail.com

