import answers as answers
import subprocess
from InquirerPy import prompt
from modules import discovery, sqli_test, xss_test, report
from utils.logger import Logger

HEAD
# Interactive prompt
# Interactive CLI Questions
b1bc7ac (Save current changes before cherry-pick)
questions = [
    {
        "type": "list",
        "name": "mode",
        "message": "Choose scan mode:",
        "choices": ["discovery", "sql", "xss", "full", "dev: cherry-pick commits"]
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

# Prompt user for answers

answers = prompt(questions)
HEAD

# Using the answers
logger = Logger(verbose=answers['verbose'])

if answers['mode'] == 'discovery':
    discovery.run(logger)
elif answers['mode'] == 'sql':
    sqli_test.run(logger)
elif answers['mode'] == 'xss':
    xss_test.run(logger)
elif answers['mode'] == 'full':
    discovery.run(logger)
    sqli_test.run(logger)
    xss_test.run(logger)

# Step 3: Export the report
report.export()

# Initialize logger with verbose/silent mode
logger = Logger(verbose=answers["verbose"])
results = []

# Mode: Discovery (with submenus)

if answers["mode"] == "discovery":
    submode_question = [
        {
            "type": "list",
            "name": "discovery_type",
            "message": "Choose discovery type:",
            "choices": ["search_engine", "dns"]
        }
    ]
    discovery_type = prompt(submode_question)["discovery_type"]
    discovery_options = {"type": discovery_type}

    if discovery_type == "search_engine":
        search_engine_questions = [
            {
                "type": "input",
                "name": "search_url",
                "message": "Search engine URL:",
                "default": "https://www.google.com"
            },
            {
                "type": "input",
                "name": "keywords_file",
                "message": "Keywords file path:",
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
        ]
        discovery_options.update(prompt(search_engine_questions))

    elif discovery_type == "dns":
        dns_questions = [
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
                "message": "Timeout per request (seconds):",
                "default": "3"
            },
            {
                "type": "input",
                "name": "alexa_rank",
                "message": "Alexa Max Rank:",
                "default": "1000000"
            },
            {
                "type": "input",
                "name": "alexa_file",
                "message": f"Alexa {'JSON' if answers['output'] == 'json' else 'CSV'} file path:",
                "default": "alexa_top_sites.json" if answers['output'] == 'json' else "alexa_top_sites.csv"
            }
        ]
        discovery_options.update(prompt(dns_questions))

    discovery.run(logger, discovery_options)

# Mode: XSS only
elif answers["mode"] == "xss":
    results = xss_test.run(logger)

# Full pipeline
elif answers["mode"] == "full":
    discovered_urls = discovery.run(logger)
    sqli_test.run(logger)
    results = xss_test.run(logger)

# Dev Mode: Cherry-pick commits

elif answers["mode"] == "dev: cherry-pick commits":
    dev_questions = [
        {
            "type": "input",
            "name": "branch",
            "message": "Target branch to cherry-pick into:",
            "default": "vuln_cli_tool"
        },
        {
            "type": "input",
            "name": "commits",
            "message": "Commit hashes to cherry-pick (comma-separated):"
        }
    ]
    dev_inputs = prompt(dev_questions)

    # Checkout the target branch
    subprocess.call(["git", "checkout", dev_inputs["branch"]])

    # Cherry-pick each commit hash
    for h in dev_inputs["commits"].split(","):
        commit = h.strip()
        if commit:
            logger.log(f"[git] Cherry-picking commit {commit}...")
            subprocess.call(["git", "cherry-pick", "-x", commit])

# Export report if results exist 
if results:
    report.save_report(results, output_format=answers["output"])
b1bc7ac (Save current changes before cherry-pick)
