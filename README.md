# headerscanner
Hacker Vlog Security Header Scanner
Overview
The Hacker Vlog Security Header Scanner is a Python-based tool designed to analyze and report on the presence and status of critical security headers in a given website. This tool helps identify potential security vulnerabilities related to missing or improperly configured HTTP headers, providing recommendations and highlighting their impact and severity.

With a look and feel inspired by classic hacking tools, the "Hacker Vlog" Scanner delivers professional-grade results in a user-friendly manner.

Features
1. Detailed Security Header Analysis: Checks for key HTTP security headers and provides information on their presence, value, and recommendations if absent.
2. Impact and Severity Ratings: Assesses the importance and criticality of each header's presence or absence.
3. Comprehensive Reporting: Generates a detailed report summarizing findings, including a timestamp, total headers checked, and a summary of present and absent headers.
4. User-Friendly Branding: Includes ASCII art and a professional introduction to give the tool a distinctive "hacker" vibe.

Security Headers Checked

1. Content-Security-Policy (CSP)
Prevents various types of attacks, including Cross-Site Scripting (XSS).
Recommendation: Define a policy to restrict content sources.

2. X-Frame-Options
Protects against clickjacking.
Recommendation: Set to DENY or SAMEORIGIN.

3. X-Content-Type-Options
Prevents MIME type sniffing.
Recommendation: Set to nosniff.

4. Strict-Transport-Security (HSTS)
Enforces HTTPS communication.
Recommendation: Enable and configure HSTS.

5. Referrer-Policy
Controls the referrer information sent with requests.
Recommendation: Use no-referrer or strict-origin-when-cross-origin.

6. Permissions-Policy
Manages access to browser features.
Recommendation: Define a policy to control feature access.

7. Expect-CT
Ensures compliance with Certificate Transparency.
Recommendation: Set to enforce Certificate Transparency.


Installation
To run the Hacker Vlog Security Header Scanner, you need Python 3 and the requests library. 
Follow these steps to get started:

1. Clone the Repository
git clone https://github.com/hackervlogofficial/headerscanner.git
cd headerscanner

2. Install Required Libraries
pip install requests

3. Run the Tool
python security_header_scanner.py

Usage
1. After starting the tool, you will be prompted to enter the URL of the website you want to scan.
2. The tool will analyze the headers and display the results in the console.
3. A detailed report will be saved in the current directory with a filename based on the scan's timestamp.

Example
Enter the URL to check for security headers: https://example.com
Checking security headers for https://example.com...
Present Header: Content-Security-Policy
  Present: Yes
  Value: default-src 'self'; img-src 'self' data:
  Status: OK

Missing Header: X-Frame-Options
  Present: No
  Description: Prevents clickjacking by controlling whether the website can be embedded in frames.
  Recommendation: Set the X-Frame-Options header to 'DENY' or 'SAMEORIGIN'.
  Impact: Medium
  Severity: High

...

Report saved as security_headers_report_20240626123045.txt

Report Format
The generated report includes:
1. Header Status: Each checked header is listed with its presence status and value if present.
2. Recommendations: Advice on how to address missing headers.
3. Summary: A summary of the total headers checked, those present or absent, and the total time taken for the scan.
4. Timestamp: Date and time when the scan was performed.

Contributing
Contributions are welcome! Feel free to open an issue or submit a pull request if you have suggestions for improvements or new features.

Fork the repository.
1. Create a new branch (git checkout -b feature-branch).
2. Commit your changes (git commit -am 'Add new feature').
3. Push to the branch (git push origin feature-branch).
4. Open a Pull Request.

License
This project is licensed under the MIT License - see the LICENSE file for details.

Acknowledgments
1. Inspired by tools like Nikto and classic hacking interfaces.
2. ASCII art created using Text to ASCII Art Generator (TAAG).

Contact
For any questions or feedback, please contact us at hackervlogofficial@gmail.com
