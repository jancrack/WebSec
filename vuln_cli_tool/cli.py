import argparse
from modules import discovery, sqli_test, xss_test, report
from utils.logger import Logger

parser = argparse.ArgumentParser(description="Vulnerability Assessment CLI Tool")

parser.add_argument('--mode', choices=['discovery', 'sqli', 'xss', 'full'], required=True)
parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
parser.add_argument('--output', choices=['json', 'csv'], default='json', help='Export format')

args = parser.parse_args()
logger = Logger()

if args.mode == 'discovery':
    discovery.run(logger)
elif args.mode == 'sqli':
    sqli_test.run(logger)
elif args.mode == 'xss':
    xss_test.run(logger)
elif args.mode == 'full':
    discovery.run(logger)
    sqli_test.run(logger)
    xss_test.run(logger)

report.exportt(format=args.output)
