# **🔐 Web Vulnerability Scanner Toolkit**
A Python-based project for automated discovery and vulnerability assessment of random websites across the internet. This toolkit focuses on detecting common web vulnerabilities such as **SQL Injection (SQLi)** and **Cross-Site Scripting (XSS)** using powerful tools like sqlmap, combined with a custom website discovery engine and CLI interface.

## **📋 Project Overview**
The project is structured as a suite of command-line utilities that work in sequence or independently:
### **1. 🌐 Website Discovery & Filtering**
**Description:**
This utility discovers random websites across the internet (e.g., via search engine scraping, domain generation, or using site lists). It filters out sites that are expected to be well-protected (e.g., domains of large corporations, government sites, or those with known high-grade protection).

**Purpose:**
To build a working list of potentially vulnerable websites for security research and testing.

**Planned Features:**

- Search engine scraping (e.g., Bing dorking or DuckDuckGo).
- DNS Scraping
- Domain list generation.
- Domain reputation or blacklist (e.g., Alexa Top Sites exclusion).
- Filtering using keywords or reputation (e.g., Alexa Top 1000).
- TLD filtering (e.g., exclude .gov, .edu, etc.).
- Keyword-based filtering (e.g., "bank", "paypal", etc.).
- Response headers and security-related HTTP headers.

### **2. 🐍 SQL Injection Scanner**
**Description:**
This utility takes a list of websites (from Step 1) and systematically tests each for **SQL Injection vulnerabilities** using the sqlmap tool.

**Purpose:**
To identify endpoints that are not properly sanitizing input and are therefore susceptible to SQLi attacks.

**Planned Features:**

- Automatic crawling of website pages.
- Parameter discovery (GET and POST).
- Integration with sqlmap for automated testing.
- Logging of vulnerable pages and filtering out secure ones.

### **3. 🧪 XSS Vulnerability Scanner (Optional)**
**Description:**
Similar to Step 2, this tool checks for **Cross-Site Scripting (XSS)** vulnerabilities on the same set of websites. It uses payload injection and analysis techniques to detect reflected and stored XSS.

**Purpose:**
To evaluate how well web applications sanitize user input against XSS attacks.

**Planned Features:**

- JavaScript payload injection.
- Detection of reflected/stored XSS in page output.
- Optional headless browser automation (e.g., using Selenium or Puppeteer).
- False positive reduction mechanisms.

### **4. 🖥️ Command-Line Interface (CLI) Controller**
**Description:**
This is the main utility that orchestrates all of the above tools. It offers a user-friendly CLI to run modules individually or together as a pipeline.

**Purpose:**
To streamline the vulnerability assessment workflow in a single terminal session.

**Planned Features:**

- Interactive CLI with menus.
- Mode selection: discovery-only, test SQLi, test XSS, full pipeline.
- Export reports to file (JSON/CSV).
- Verbose and silent modes.

## **📁 Project Structure (Planned)**
web-vuln-scanner/

│

├── discover.py           # Step 1: Website discovery

├── sqli\_scanner.py       # Step 2: SQL injection scanner

├── xss\_scanner.py        # Step 3: XSS vulnerability scanner

├── cli.py                # Step 4: CLI integration

├── utils/                # Helper modules and tools

├── results/              # Output directory for logs and reports

├── requirements.txt      # Python dependencies

README.md             # Project documentation

## **⚠️ Legal Disclaimer**
This project is intended for **educational and ethical research purposes only**. You must have explicit permission to scan and test any website with this tool. Unauthorized scanning or intrusion testing is **illegal** and strictly prohibited.

## **📌 Future Enhancements**
- Web/GUI dashboard for visualization
- CVE detection
- Multi-threaded scanning

