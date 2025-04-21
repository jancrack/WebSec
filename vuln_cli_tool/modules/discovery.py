def run(logger, options=None):
    logger.log("[*] Running discovery...")

    if options is None or "type" not in options:
        logger.log("[-] No discovery type specified. Exiting.")
        return []

    found_urls = []

    if options["type"] == "search_engine":
        search_url = options.get("search_url", "https://www.google.com")
        keywords_file = options.get("keywords_file", "words.txt")
        xpath = options.get("xpath", "//div[@class='g']/a")
        timeout = int(options.get("timeout", 5))

        logger.log(f"Search Engine Discovery:")
        logger.log(f"    URL: {search_url}")
        logger.log(f"    Keywords File: {keywords_file}")
        logger.log(f"    XPath: {xpath}")
        logger.log(f"    Timeout: {timeout}s")

        found_urls = [
            "http://example.com/search?q=login",
            "http://example.com/search?q=admin"
        ]

    elif options["type"] == "dns":
        ips = options.get("ips", "")
        dns_server = options.get("dns_server", "1.1.1.1")
        threads = int(options.get("threads", 20))
        ports = [int(p) for p in options.get("ports", "80,8000,443").split(",")]
        timeout = int(options.get("timeout", 1))
        alexa_rank = int(options.get("alexa_rank", 100))
        alexa_csv = options.get("alexa_csv", "")

        logger.log(f"[🌐] DNS Discovery:")
        logger.log(f"    IPs: {ips}")
        logger.log(f"    DNS Server: {dns_server}")
        logger.log(f"    Ports: {ports}")
        logger.log(f"    Threads: {threads}")
        logger.log(f"    Timeout: {timeout}s")
        logger.log(f"    Alexa Rank Limit: {alexa_rank}")
        logger.log(f"    Alexa CSV: {alexa_csv}")

        found_urls = [
            f"http://{ip}:{port}" for ip in ["192.168.0.100", "192.168.0.101"] for port in ports
        ]

    else:
        logger.log("[-] Unknown discovery type.")
        return []

    logger.log(f"[+] Discovered {len(found_urls)} URLs.")
    return found_urls
