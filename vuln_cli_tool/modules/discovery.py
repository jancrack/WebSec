def run(logger, options=None):
    logger.log("[*] Running discovery...")

    # Exit early if no options or no discovery type is provided
    if options is None or "type" not in options:
        logger.log("[-] No discovery type specified. Exiting.")
        return []

    found_urls = []

    # Search Engine Discovery
    if options["type"] == "search_engine":
        # Extract search engine parameters
        search_url = options.get("search_url", "https://www.google.com")
        keywords_file = options.get("keywords_file", "words.txt")
        xpath = options.get("xpath", "//div[@class='g']/a")
        timeout = int(options.get("timeout", 5))

        # Log selected options
        logger.log("Search Engine Discovery:")
        logger.log(f"    URL: {search_url}")
        logger.log(f"    Keywords File: {keywords_file}")
        logger.log(f"    XPath: {xpath}")
        logger.log(f"    Timeout: {timeout}s")

        found_urls = [
            "http://example.com/search?q=login",
            "http://example.com/search?q=admin"
        ]

    # DNS Discovery
    elif options["type"] == "dns":

        # Extract DNS and network scan parameters

        ips = options.get("ips", "")
        dns_server = options.get("dns_server", "1.1.1.1")
        threads = int(options.get("threads", 20))
        ports = [int(p) for p in options.get("ports", "80,8000,443").split(",")]
        timeout = int(options.get("timeout", 5))
        alexa_rank = int(options.get("alexa_rank", 100))
        alexa_file = options.get("alexa_file", "")

        # Log DNS discovery config
        logger.log("[🌐] DNS Discovery:")
        logger.log(f"    IPs: {ips}")
        logger.log(f"    DNS Server: {dns_server}")
        logger.log(f"    Ports: {ports}")
        logger.log(f"    Threads: {threads}")
        logger.log(f"    Timeout: {timeout}s")
        logger.log(f"    Alexa Rank Limit: {alexa_rank}")

        # Display Alexa file format based on extension
        if alexa_file.endswith(".json"):
            logger.log(f"    Alexa JSON: {alexa_file}")
        elif alexa_file.endswith(".csv"):
            logger.log(f"    Alexa CSV: {alexa_file}")
        else:
            logger.log(f"    Alexa File: {alexa_file} (unknown format)")

        found_urls = [
            f"http://{ip}:{port}" for ip in ["192.168.0.100", "192.168.0.101"] for port in ports
        ]

    # Unknown Discovery Type
    else:
        logger.log("[-] Unknown discovery type.")
        return []

    # Final log with number of URLs found
    logger.log(f"[+] Discovered {len(found_urls)} URLs.")
    return found_urls
