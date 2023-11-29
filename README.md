# RCE_Vuln_Finder
To use the provided Burp Suite extension for testing your website (e.g., `test.com`), you need to follow these steps:

### Prerequisites:
1. **Install Burp Suite:**
   - If you haven't already, download and install Burp Suite from the [official website](https://portswigger.net/burp).

2. **Open Burp Suite:**
   - Open Burp Suite and make sure it's running.

### Load the Extension:
1. **Load the Extension:**
   - Save the provided Python code in a file, for example, `vuln.py`.
   - In Burp Suite, go to the "Extender" tab.
   - Click on the "Extensions" tab within the "Extender" tab.
   - Click the "Add" button and select the Python file (`vuln.py`) to load the extension.

2. **Verify Loading:**
   - Ensure that the extension appears in the list of loaded extensions.

### Configure Scanning:
1. **Configure Scope:**
   - Go to the "Target" tab and configure the scope to include your target website (`test.com`).

2. **Configure Scanner:**
   - In the "Scanner" tab, go to the "Options" sub-tab.
   - Configure the scanner options as needed.

### Run Passive Scan:
1. **Initiate Passive Scan:**
   - Visit your website (`test.com`) in a web browser or use other tools to interact with it.
   - The extension will passively scan responses for the presence of the string "eval(".

### Run Active Scan:
1. **Initiate Active Scan:**
   - Go to the "Target" tab and select your website (`test.com`).
   - Right-click and choose "Active Scan."

### View Scan Results:
1. **Check Scan Results:**
   - Go to the "Scanner" tab to monitor the progress of the scan.
   - Check the "Scan Issues" tab to view any identified issues.

### Interpret Results:
1. **Review Issues:**
   - The extension will create issues if it finds potential RCE or injection vulnerabilities.
   - Review the details of each issue to understand the identified problems.

### Important Notes:
- Ensure that you have proper authorization to perform security testing on the target website.
- This extension is a simplified example, and its effectiveness may vary depending on the nature of your website and the vulnerabilities present.
- Understand the results and perform additional manual testing to verify and validate any identified issues.

Remember to use security testing tools responsibly and only on systems that you are authorized to test. Unauthorized testing can lead to legal consequences.
