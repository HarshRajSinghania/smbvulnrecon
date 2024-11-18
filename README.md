# SMBVulnRecon

SMBVulnRecon is a Python-based SMB vulnerability scanner that identifies common vulnerabilities in SMB servers, including EternalBlue, SMBGhost, PrintNightmare, and more. It tests for misconfigurations, unpatched systems, and weak SMB settings, providing an all-in-one solution for SMB reconnaissance.
Features

    Tests for SMB Vulnerabilities:
        EternalBlue (CVE-2017-0144)
        SMBGhost (CVE-2020-0796)
        PrintNightmare (CVE-2021-1675)
        SMB Signing Disabled (CVE-2022-38023)
        SMBv1 Denial-of-Service (CVE-2019-0703)
        Null Session Enumeration
        SMB Share Permissions Audit

    Customizable Credentials: Supports user-provided credentials for authenticated SMB tests.

    Sequential Testing: Executes all tests in sequence, with clear results for each.

## Installation
### Prerequisites

    Python 3.6 or higher
    pip package manager

### Install Dependencies

Clone the repository:

git clone https://github.com/your-username/smbvulnrecon.git
cd smbvulnrecon

Install required libraries:

    pip install -r requirements.txt

## Usage
Run the Script

Execute the script:

    python3 smbvulnrecon.py

Input the target IP and credentials when prompted:

    Enter target IP address: 192.168.1.10
    Enter username (default: guest): admin
    Enter password (default: guest): admin123

    Review the results displayed for each test.

## Output

Each vulnerability test provides one of the following outcomes:

    [+] Indicates the target is potentially vulnerable.
    [-] Indicates the target is not vulnerable.
    [!] Indicates an error occurred during the test.

## Test Descriptions
Vulnerability	CVE ID	Description
EternalBlue	CVE-2017-0144	Tests for SMBv1 exploitability.
SMBGhost	CVE-2020-0796	Checks for SMBv3 buffer overflow vulnerability.
PrintNightmare	CVE-2021-1675	Verifies if the Print Spooler service is running, indicating potential risk.
SMB Signing Disabled	CVE-2022-38023	Identifies misconfigurations in SMB signing settings.
SMBv1 DoS	CVE-2019-0703	Sends a crafted payload to check for denial-of-service conditions.
Null Session	-	Checks for anonymous SMB share access.
Share Permissions	-	Audits SMB shares for overly permissive access rights.
## Customization

You can modify the run_all_tests function in the script to:

Skip specific tests.
Add new tests for additional SMB-related vulnerabilities.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
## Disclaimer

This tool is intended for educational purposes and authorized penetration testing only. Unauthorized use against systems without permission is illegal.
## Contributions

Feel free to fork the repository and submit pull requests for new features or bug fixes.

Enjoy using SMBVulnRecon! 😊
