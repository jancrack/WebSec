from InquirerPy import prompt
from modules import discovery, sqli_test, xss_test, report
from utils.logger import Logger


def run():
    # Main Questions
    questions = [
        {
            "type": "list",
            "name": "mode",
            "message": "Choose scan mode:",
            "choices": ["discovery", "sql", "xss", "full"],
        },
        {
            "type": "confirm",
            "name": "verbose",
            "message": "Enable verbose mode?",
            "default": True,
        },
        {
            "type": "list",
            "name": "output",
            "message": "Choose export format:",
            "choices": ["json", "csv"],
        },
    ]

    answers = prompt(questions)
    logger = Logger(verbose=answers["verbose"])
    results = []

    # Discovery mode with sub-options
    if answers["mode"] == "discovery":
        discovery_type = prompt(
            [
                {
                    "type": "list",
                    "name": "discovery_type",
                    "message": "Choose discovery type:",
                    "choices": ["search_engine", "dns"],
                }
            ]
        )["discovery_type"]

        discovery_options = {"type": discovery_type}

        if discovery_type == "search_engine":
            discovery_options.update(
                prompt(
                    [
                        {
                            "type": "input",
                            "name": "search_url",
                            "message": "Search engine URL with query param (eg. google.com/search?q=):",
                            "default": "duckduckgo.com/?q=",
                        },
                        {
                            "type": "input",
                            "name": "xpath",
                            "message": "Search result XPath:",
                            "default": "//*/div/h2/a",
                        },
                        {
                            "type": "input",
                            "name": "keywords_file",
                            "message": "Keywords file path:",
                            "default": "words.txt",
                        },
                        {
                            "type": "input",
                            "name": "depth",
                            "message": "Search depth:",
                            "default": "1",
                        },
                        {
                            "type": "input",
                            "name": "next_page_xpath",
                            "message": "Next page xpath:",
                            "default": '//*[@id="more-results"]',
                        },
                        {
                            "type": "input",
                            "name": "alexa_csv",
                            "message": "Alexa top sites CSV file path:",
                            "default": "alexa_top_1M.csv",
                        },
                        {
                            "type": "input",
                            "name": "alexa_max_rank",
                            "message": "Alexa Max Rank:",
                            "default": "1000000",
                        },
                        {
                            "type": "input",
                            "name": "threads",
                            "message": "Number of threads:",
                            "default": "20",
                        },
                        {
                            "type": "input",
                            "name": "delay",
                            "message": "Thread delay (seconds):",
                            "default": "0.5",
                        },
                    ]
                )
            )

        elif discovery_type == "dns":
            discovery_options.update(
                prompt(
                    [
                        {
                            "type": "input",
                            "name": "ips",
                            "message": "Target IPs (e.g. 192.168.0.100/29 or 192.168.0.101 or 192.168.0.100..192.168.0.120):",
                        },
                        {
                            "type": "input",
                            "name": "dns_server",
                            "message": "DNS server to use:",
                            "default": "1.1.1.1",
                        },
                        {
                            "type": "input",
                            "name": "threads",
                            "message": "Number of threads:",
                            "default": "20",
                        },
                        {
                            "type": "input",
                            "name": "ports",
                            "message": "Ports to test (comma separated):",
                            "default": "80,443",
                        },
                        {
                            "type": "input",
                            "name": "timeout",
                            "message": "Timeout per request (seconds):",
                            "default": "3",
                        },
                        {
                            "type": "input",
                            "name": "alexa_rank",
                            "message": "Alexa Max Rank:",
                            "default": "1000000",
                        },
                        {
                            "type": "input",
                            "name": "alexa_file",
                            "message": f"Alexa top sites CSV file path:",
                            "default": "alexa_top_1M.csv",
                        },
                    ]
                )
            )

        # Run discovery
        discovery_options.update(answers)
        discovery.run(logger, discovery_options)

    # SQLi scan
    elif answers["mode"] == "sql":
        sql_optioons = prompt(
            [
                {
                    "type": "input",
                    "name": "filepath",
                    "message": f"SQLMap portable installition main script path:",
                    "default": "vuln_cli_tool/utils/sqlmap-master/sqlmap.py",
                },{
                    "type": "input",
                    "name": "url",
                    "message": f"URL to attack:",
                    "default": "http://testphp.vulnweb.com/listproducts.php?cat=1",
                }
            ]
        )
        results += sqli_test.run(logger,sql_optioons.get("filepath"), [sql_optioons.get("url")])

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
            "alexa_file": (
                "alexa_top_sites.json"
                if answers["output"] == "json"
                else "alexa_top_sites.csv"
            ),
        }

        discovered_urls = discovery.run(logger, options=default_discovery_options)
        sqli_test.run(logger)
        results = xss_test.run(logger)

    # Save results if available
    if results:
        report.save_report(results, output_format=answers["output"])


if __name__ == "__main__":
    run()
