from InquirerPy import prompt
from modules import discovery, sqli_test, xss_test, report
from utils.logger import Logger

# Interactive CLI questions
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

# Collect answers from user
answers = prompt(questions)

# Initialize logger
logger = Logger(verbose=answers["verbose"])

# Initialize empty results list
results = []

# Run selected scan mode
if answers["mode"] == "discovery":
    discovery.run(logger)

elif answers["mode"] == "sql":
    sqli_test.run(logger)

elif answers["mode"] == "xss":
    results = xss_test.run(logger) or []

elif answers["mode"] == "full":
    discovery.run(logger)
    sqli_test.run(logger)
    results = xss_test.run(logger) or []

# Export results (if any)
report.save_report(results, output_format=answers["output"])
