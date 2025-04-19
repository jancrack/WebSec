from InquirerPy import prompt
from modules import discovery, sqli_test, xss_test, report
from utils.logger import Logger

# Interactive prompt for user input
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

# Logger setup
logger = Logger(verbose=answers['verbose'])

# Run the appropriate scan mode based on the user input
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

# Save the report in the chosen format (json or csv)
report.save_report(xss_test.results, output_format=answers['output'])
