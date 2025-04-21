from InquirerPy import prompt
from modules import discovery, sqli_test, xss_test, report
from utils.logger import Logger

# Main questions
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

# 📦 Handle discovery sub-options
discovery_options = {}
if answers["mode"] == "discovery":
    submode_question = [
        {
            "type": "list",
            "name": "discovery_type",
            "message": "Choose discovery type:",
            "choices": ["search_engine", "dns"]
        }
    ]
    submode = prompt(submode_question)["discovery_type"]

    if submode == "search_engine":
        discovery_options = prompt([
            {
                "type": "input",
                "name": "search_url",
                "message": "Search engine URL:",
                "default": "https://www.google.com"
            },
            {
                "type": "input",
                "name": "keywords_file",
                "message": "Keywords file:",
                "default": "words.txt"
            },
            {
                "type": "input",
                "name": "xpath",
                "message": "Search result XPath:",
                "default": "//div[@class='g']/a"
            },
            {
                "type": "input",
                "name": "timeout",
                "message": "Request timeout (seconds):",
                "default": "5"
            }
        ])
        discovery_options["type"] = "search_engine"

    elif submode == "dns":
        discovery_options = prompt([
            {
                "type": "input",
                "name": "ips",
                "message": "Target IPs (e.g. 192.168.0.100/29 or 192.168.0.100,192.168.0.101):"
            },
            {
                "type": "input",
                "name": "dns_server",
                "message": "DNS server to use:",
                "default": "1.1.1.1"
            },
            {
                "type": "input",
                "name": "threads",
                "message": "Number of threads:",
                "default": "20"
            },
            {
                "type": "input",
                "name": "ports",
                "message": "Ports to test (comma separated):",
                "default": "80,8000,443"
            },
            {
                "type": "input",
                "name": "timeout",
                "message": "Timeout per request (sec):",
                "default": "1"
            },
            {
                "type": "input",
                "name": "alexa_rank",
                "message": "Alexa Max Rank:",
                "default": "100"
            },
            {
                "type": "input",
                "name": "alexa_csv",
                "message": "Alexa CSV file (path):"
            }
        ])
        discovery_options["type"] = "dns"

    # 🔍 Call discovery with parameters
    discovery.run(logger, discovery_options)
