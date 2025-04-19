from InquirerPy import prompt
from modules import discovery, sqli_test, xss_test, report
from utils.logger import Logger

# Interactive prompt
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
