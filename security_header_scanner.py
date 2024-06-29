import requests
import datetime
import time

# ASCII Art Branding for "Hacker Vlog"
def print_branding():
    branding_text = """
  _    _            _           _    __     __         
 | |  | |          | |         | |   \ \   / /         
 | |__| | __ _  ___| | ___ __ _| |_   \ \_/ /__  _   _ 
 |  __  |/ _` |/ __| |/ / '__| | __|   \   / _ \| | | |
 | |  | | (_| | (__|   <| |  | | |_     | | (_) | |_| |
 |_|  |_|\__,_|\___|_|\_\_|  |_|\__|    |_|\___/ \__,_|
                                                                                      
  """
    print(branding_text)
    print("="*60)
    print("        Welcome to the Hacker Vlog Security Header Scanner")
    print("="*60)
    print("Checking your website's security headers for best practices.\n")

# Define the security headers and their recommendations
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Prevents a wide range of attacks including Cross-Site Scripting (XSS) by specifying allowed sources for content.",
        "recommendation": "Define a Content-Security-Policy header to restrict the sources of content.",
        "impact": "High",
        "severity": "Critical"
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking by controlling whether the website can be embedded in frames.",
        "recommendation": "Set the X-Frame-Options header to 'DENY' or 'SAMEORIGIN'.",
        "impact": "Medium",
        "severity": "High"
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing, which can lead to security vulnerabilities if browsers interpret files as a different type than intended.",
        "recommendation": "Set the X-Content-Type-Options header to 'nosniff'.",
        "impact": "Medium",
        "severity": "High"
    },
    "Strict-Transport-Security": {
        "description": "Ensures browsers only communicate with the site using HTTPS, preventing man-in-the-middle attacks.",
        "recommendation": "Set the Strict-Transport-Security header to enforce HTTPS usage.",
        "impact": "High",
        "severity": "Critical"
    },
    "Referrer-Policy": {
        "description": "Controls the amount of referrer information sent with requests to other sites.",
        "recommendation": "Set the Referrer-Policy header to 'no-referrer' or 'strict-origin-when-cross-origin'.",
        "impact": "Low",
        "severity": "Medium"
    },
    "Permissions-Policy": {
        "description": "Manages which APIs and browser features are accessible in the context of a site.",
        "recommendation": "Set the Permissions-Policy header to control feature access (e.g., 'geolocation', 'microphone').",
        "impact": "Medium",
        "severity": "Medium"
    },
    "Expect-CT": {
        "description": "Helps detect misissued certificates and ensure compliance with Certificate Transparency.",
        "recommendation": "Set the Expect-CT header to enforce Certificate Transparency.",
        "impact": "Medium",
        "severity": "Medium"
    }
}

def check_headers(url):
    # Start timing the scan
    start_time = time.time()
    
    try:
        response = requests.get(url)
        headers = response.headers

        # Initialize counts and results list
        present_count = 0
        absent_count = 0
        results = []

        print(f"\nChecking security headers for {url}...\n")
        
        for header, details in SECURITY_HEADERS.items():
            if header not in headers:
                absent_count += 1
                result = {
                    "header": header,
                    "present": "No",
                    "description": details["description"],
                    "recommendation": details["recommendation"],
                    "impact": details["impact"],
                    "severity": details["severity"]
                }
                print(f"Missing Header: {header}")
                print(f"  Present: No")
                print(f"  Description: {details['description']}")
                print(f"  Recommendation: {details['recommendation']}")
                print(f"  Impact: {details['impact']}")
                print(f"  Severity: {details['severity']}\n")
            else:
                present_count += 1
                result = {
                    "header": header,
                    "present": "Yes",
                    "value": headers[header],
                    "status": "OK"
                }
                print(f"Present Header: {header}")
                print(f"  Present: Yes")
                print(f"  Value: {headers[header]}")
                print(f"  Status: OK\n")
            
            results.append(result)
        
        # Calculate total time taken
        total_time = time.time() - start_time
        
        # Summary of results
        summary = {
            "url": url,
            "total_headers_checked": len(SECURITY_HEADERS),
            "headers_present": present_count,
            "headers_absent": absent_count,
            "scan_duration_seconds": total_time,
            "scan_date_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        print(f"Summary of results for {url}:")
        print(f"  Total Headers Checked: {summary['total_headers_checked']}")
        print(f"  Headers Present: {summary['headers_present']}")
        print(f"  Headers Absent: {summary['headers_absent']}")
        print(f"  Total Time Taken: {summary['scan_duration_seconds']:.2f} seconds")
        print(f"  Scan Date & Time: {summary['scan_date_time']}")
        
        # Exporting the report
        report_filename = f"security_headers_report_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
        with open(report_filename, "w") as report_file:
            report_file.write(f"Hacker Vlog Header Scan Report for {url}\n")
            report_file.write("="*60 + "\n")
            for result in results:
                report_file.write(f"{result['header']}:\n")
                if result["present"] == "Yes":
                    report_file.write(f"  Present: {result['present']}\n")
                    report_file.write(f"  Value: {result['value']}\n")
                    report_file.write(f"  Status: {result['status']}\n\n")
                else:
                    report_file.write(f"  Present: {result['present']}\n")
                    report_file.write(f"  Description: {result['description']}\n")
                    report_file.write(f"  Recommendation: {result['recommendation']}\n")
                    report_file.write(f"  Impact: {result['impact']}\n")
                    report_file.write(f"  Severity: {result['severity']}\n\n")
            report_file.write(f"Summary:\n")
            report_file.write(f"  Total Headers Checked: {summary['total_headers_checked']}\n")
            report_file.write(f"  Headers Present: {summary['headers_present']}\n")
            report_file.write(f"  Headers Absent: {summary['headers_absent']}\n")
            report_file.write(f"  Total Time Taken: {summary['scan_duration_seconds']:.2f} seconds\n")
            report_file.write(f"  Scan Date & Time: {summary['scan_date_time']}\n")
        
        print(f"\nReport saved as {report_filename}")

    except requests.RequestException as e:
        print(f"Error accessing {url}: {e}")

# Print branding
print_branding()

# Ask the user for the URL to check
url = input("Enter the URL to check for security headers: ")
check_headers(url)
