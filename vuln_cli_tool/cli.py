import os
from InquirerPy import prompt
from utils.logger import Logger
from modules import discovery, sqli_test, xss_test, report


def run():
    os.makedirs("vuln_cli_tool/reports", exist_ok=True)

    # Main Questions
    general_options = [
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
    discovery_type_options = [
        {
            "type": "list",
            "name": "discovery_type",
            "message": "Choose discovery type:",
            "choices": ["search_engine", "dns"],
        }
    ]
    discovery_search_engine_options = [
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
    discovery_dns_optons = [
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
            "name": "ports",
            "message": "Ports to test (comma separated):",
            "default": "80,443",
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
        {
            "type": "input",
            "name": "timeout",
            "message": "Timeout per request (seconds):",
            "default": "3",
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
    xss_options = []
    xss_standalone_options = xss_options + [
        {
            "type": "input",
            "name": "url",
            "message": "URL to attack:",
            "default": "http://testphp.vulnweb.com/search.php?test=query",
        }
    ]
    sqli_options = [
        {
            "type": "input",
            "name": "filepath",
            "message": "SQLMap portable installition main script path:",
            "default": "vuln_cli_tool/utils/sqlmap-master/sqlmap.py",
        },
    ]
    sqli_standalone_options = sqli_options + [
        {
            "type": "input",
            "name": "url",
            "message": "URL to attack:",
            "default": "http://testphp.vulnweb.com/listproducts.php?cat=1",
        }
    ]

    answers = prompt(general_options)
    logger = Logger(verbose=answers["verbose"])
    results = []

    # Discovery mode with sub-options
    if answers["mode"] == "discovery":

        discovery_type = prompt(discovery_type_options)["discovery_type"]

        discovery_options = {"type": discovery_type}

        if discovery_type == "search_engine":

            discovery_options.update(prompt(discovery_search_engine_options))

        elif discovery_type == "dns":

            discovery_options.update(prompt(discovery_dns_optons))

        # Run discovery
        discovery_options.update(answers)
        discovery.run(logger, discovery_options)

    # SQLi scan
    elif answers["mode"] == "sql":
        sql_options_selection = prompt(sqli_standalone_options)
        results += sqli_test.run(
            logger,
            sql_options_selection.get("filepath"),
            [sql_options_selection.get("url")],
        )

    # XSS scan
    elif answers["mode"] == "xss":
        xss_standalone_options_selection = prompt(xss_standalone_options)
        results += xss_test.run(logger, xss_standalone_options_selection)

    # Full pipeline (discovery + SQLi + XSS)
    elif answers["mode"] == "full":
        # Provide default discovery options (DNS or Search Engine)
        discovery_type = prompt(discovery_type_options)["discovery_type"]

        discovery_options = {"type": discovery_type}

        if discovery_type == "search_engine":

            discovery_options.update(prompt(discovery_search_engine_options))

        elif discovery_type == "dns":

            discovery_options.update(prompt(discovery_dns_optons))

        sqli_options_selection = prompt(sqli_options)
        xss_options_selection = prompt(xss_options)

        # Run discovery
        discovery_options.update(answers)

        discovery_result_addresses = discovery.run(logger, discovery_options)
        sqli_test.run(
            logger, sqli_options_selection.get("filepath"), discovery_result_addresses
        )
        results = xss_test.run(
            logger, xss_options_selection, discovery_result_addresses
        )

    # Save results if available
    if results:
        report.save_report(results, output_format=answers["output"])


if __name__ == "__main__":
    run()
