from InquirerPy import prompt
from modules import discovery, sqli_test, xss_test, report
from utils.logger import Logger
import subprocess

# Main Questions
questions = [
    {
        "type": "list",
        "name": "mode",
        "message": "Choose scan mode:",
        "choices": ["discovery", "sql", "xss", "full"]
    },
    {
        "type": "confirm",
        "name": "verbose",
        "message": "Enable verbose mode?",
        "default": True
    },
    {
        "type": "list",
        "name": "output",
        "message": "Choose export format:",
        "choices": ["json", "csv"]
    }
]

answers = prompt(questions)
logger = Logger(verbose=answers["verbose"])
results = []

# Discovery mode with sub-options
if answers["mode"] == "discovery":
    discovery_type = prompt([{
        "type": "list",
        "name": "discovery_type",
        "message": "Choose discovery type:",
        "choices": ["search_engine", "dns"]
    }])["discovery_type"]

    discovery_options = {"type": discovery_type}

    if discovery_type == "search_engine":
        discovery_options.update(prompt([
            {"type": "input", "name": "search_url", "message": "Search engine URL:", "default": "https://www.google.com"},
            {"type": "input", "name": "keywords_file", "message": "Keywords file path:", "default": "words.txt"},
            {"type": "input", "name": "xpath", "message": "Search result XPath:", "default": "//div[@class='g']/a"},
            {"type": "input", "name": "timeout", "message": "Request timeout (seconds):", "default": "5"}
        ]))

    elif discovery_type == "dns":
        discovery_options.update(prompt([
            {"type": "input", "name": "ips", "message": "Target IPs (e.g. 192.168.0.100/29 or 192.168.0.101):"},
            {"type": "input", "name": "dns_server", "message": "DNS server to use:", "default": "1.1.1.1"},
            {"type": "input", "name": "threads", "message": "Number of threads:", "default": "20"},
            {"type": "input", "name": "ports", "message": "Ports to test (comma separated):", "default": "80,8000,443"},
            {"type": "input", "name": "timeout", "message": "Timeout per request (seconds):", "default": "3"},
            {"type": "input", "name": "alexa_rank", "message": "Alexa Max Rank:", "default": "1000000"},
            {"type": "input", "name": "alexa_file", "message": f"Alexa {'JSON' if answers['output'] == 'json' else 'CSV'} file path:", "default": "alexa_top_sites.json" if answers['output'] == 'json' else "alexa_top_sites.csv"}
        ]))

    # Run discovery
    discovery.run(logger, discovery_options)

# SQLi scan 
elif answers["mode"] == "sql":
    results += sqli_test.run(logger)

# XSS scan
elif answers["mode"] == "xss":
    results += xss_test.run(logger)

# Full pipeline (discovery + SQLi + XSS)
elif answers["mode"] == "full":
    # Provide default discovery options (DNS or Search Engine)
    default_discovery_options = {
        "type": "dns",
        "ips": "192.168.0.100,192.168.0.101",
        "dns_server": "1.1.1.1",
        "threads": 10,
        "ports": "80,443",
        "timeout": 1,
        "alexa_rank": 100,
        "alexa_file": "alexa_top_sites.json" if answers['output'] == "json" else "alexa_top_sites.csv"
    }

    discovered_urls = discovery.run(logger, options=default_discovery_options)
    sqli_test.run(logger)
    results = xss_test.run(logger)


# Save results if available
if results:
    report.save_report(results, output_format=answers["output"])
