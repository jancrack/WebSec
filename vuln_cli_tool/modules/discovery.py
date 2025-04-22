import requests
from urllib.parse import urlparse
import os

def fetch_url(url, timeout=5):
    """
    Attempts to fetch a URL with SSL verification first,
    then retries without verification if an SSL error occurs.
    """
    try:
        return requests.get(url, timeout=timeout, verify=True).text
    except requests.exceptions.SSLError:
        print(f"[!] SSL error on {url}, retrying without verification...")
        try:
            return requests.get(url, timeout=timeout, verify=False).text
        except Exception as e:
            print(f"[!] Failed to fetch {url}: {e}")
            return None
    except Exception as e:
        print(f"[!] Request failed for {url}: {e}")
        return None


def run(logger, options=None):
    logger.log("[*] Running discovery...")

    if options is None or "type" not in options:
        logger.log("[-] No discovery type specified. Exiting.")
        return []

    found_urls = []

    # === Search Engine Discovery ===
    if options["type"] == "search_engine":
        search_url = options.get("search_url", "https://www.google.com")
        keywords_file = options.get("keywords_file", "words.txt")
        xpath = options.get("xpath", "//div[@class='g']/a")
        timeout = int(options.get("timeout", 5))

        logger.log("Search Engine Discovery:")
        logger.log(f"    URL: {search_url}")
        logger.log(f"    Keywords File: {keywords_file}")
        logger.log(f"    XPath: {xpath}")
        logger.log(f"    Timeout: {timeout}s")

        try:
            with open(keywords_file, 'r', encoding='utf-8') as f:
                keywords = [line.strip() for line in f.readlines()]
        except Exception as e:
            logger.log(f"[!] Failed to read keywords file: {e}")
            return []

        for word in keywords:
            test_url = f"{search_url}/search?q={word}"
            html = fetch_url(test_url, timeout=timeout)
            if html:
                logger.log(f"[✓] Fetched: {test_url}")
                found_urls.append(test_url)

        if not found_urls:
            logger.log("[!] No URLs found from search engine.")

    # === DNS Discovery ===
    elif options["type"] == "dns":
        ips = options.get("ips", "")
        dns_server = options.get("dns_server", "1.1.1.1")
        threads = int(options.get("threads", 20))
        ports = [int(p) for p in options.get("ports", "80,8000,443").split(",")]
        timeout = int(options.get("timeout", 1))
        alexa_rank = int(options.get("alexa_rank", 100))
        alexa_file = options.get("alexa_file", "")

        logger.log("DNS Discovery:")
        logger.log(f"    IPs: {ips}")
        logger.log(f"    DNS Server: {dns_server}")
        logger.log(f"    Ports: {ports}")
        logger.log(f"    Threads: {threads}")
        logger.log(f"    Timeout: {timeout}s")
        logger.log(f"    Alexa Rank Limit: {alexa_rank}")

        if alexa_file.endswith(".json"):
            logger.log(f"    Alexa JSON: {alexa_file}")
        elif alexa_file.endswith(".csv"):
            logger.log(f"    Alexa CSV: {alexa_file}")
        else:
            logger.log(f"    Alexa File: {alexa_file} (unknown format)")

        # Simulated IP and port scan
        simulated_ips = ["192.168.0.100", "192.168.0.101"]
        found_urls = [
            f"http://{ip}:{port}" for ip in simulated_ips for port in ports
        ]

    else:
        logger.log("[-] Unknown discovery type.")
        return []

    logger.log(f"[+] Discovered {len(found_urls)} URLs.")
    return found_urls
