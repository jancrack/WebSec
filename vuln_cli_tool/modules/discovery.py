import os
import ssl
import json
import time
import random
import socket
import ipaddress
import dns.resolver
import pandas as pd
import dns.reversename
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_DNS_SERVER: str = "8.8.8.8"
DEFAULT_WEB_TIMEOUT: int = 3
DEFAULT_WEB_PORTS: list[int] = [80, 8080, 8008, 8000, 8888, 443]
DEFAULT_THREADS: int = 20
DEFAULT_THREADING_DELAY: float = 0.5


def read_alexa_top_csv(
    filepath: str,
    min_rank: int = 0,
    max_rank: int = 99,
) -> list[str]:
    """
    @Returns
        A list of urls from a sorted csv file with top sites with two columns, "rank" and "site"
    @Parameters
        str filepath - the path of the csv file
        int min_rank - start rank to read from
        int max_rank - max rank to stop reading at
    """
    df = pd.read_csv(filepath)
    return df["site"].to_list()[min_rank:max_rank]


def get_hosts_in_network(network_ip: str, prefix: int) -> list[str]:
    """
    @Returns
        A list of string ip addresses that are in a network with given address and prefix
    @Parameters
        str network_ip - address of the network
        int prefix - the bit prefix of the network
    """
    network_ip = ipaddress.ip_network(network_ip + "/" + str(prefix))
    return [str(host) for host in network_ip.hosts()]


def get_hosts_in_range(min_address: str, max_address: str) -> list[str]:
    """
    @Returns
        A list of string ip addresses that are between the start and end address range
    @Parameters
        str min_address - start address of the range (inclusive)
        str max_address - end address of the range (inclusive)
    """
    min_address = ipaddress.ip_address(min_address)
    max_address = ipaddress.ip_address(max_address)
    return [
        str(ipaddress.ip_address(addr))
        for addr in range(int(min_address), int(max_address) + 1)
    ]


def reverse_dns(
    ip: str, dns_server: str = DEFAULT_DNS_SERVER, delay: float = 0
) -> tuple[str, str | None]:
    """
    @Returns
        A tuple of the given ip and the result from the DNS query or None
    @Parameters
        str ip - address of the target
        str dns_server - ip address of the dns server
    """
    time.sleep(delay)
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        reverse_name = dns.reversename.from_address(ip)
        answer = resolver.resolve(reverse_name, "PTR")
        return ip, str(answer[0])
    except Exception as e:
        print("Warning:", e)
        return ip, None


def reverse_dns_threaded(
    ips: list[str],
    dns_server: str = DEFAULT_DNS_SERVER,
    max_threads: int = DEFAULT_THREADS,
    delay: float = DEFAULT_THREADING_DELAY,
) -> dict[str : str | None]:
    """
    @Returns
        A dict with ip addresses, corresponding to the result of the reverse dns query from reverse_dns()
    @Parameters
        list[str] ips - addresses of the targets
        str dns_server - ip address of the dns server
        int max_threads - how many threads to run concurrently
    """
    results = {}
    with ThreadPoolExecutor(max_threads) as executor:
        futures = {
            executor.submit(reverse_dns, ips[i], dns_server, (i + 1) * delay): ips[i]
            for i in range(len(ips))
        }
        for future in as_completed(futures):
            ip, domain = future.result()
            results[ip] = domain
    return results


def has_web_service(
    ip: str,
    ports: list[int] = DEFAULT_WEB_PORTS,
    timeout: int = DEFAULT_WEB_TIMEOUT,
    delay: float = 0,
) -> tuple[str, bool]:
    time.sleep(delay)
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return ip, True
        except (socket.timeout, ConnectionRefusedError, OSError):
            continue
    return ip, False


def has_web_service_threaded(
    addresses: list[str],
    ports: list[int] = DEFAULT_WEB_PORTS,
    timeout: int = DEFAULT_WEB_TIMEOUT,
    max_threads: int = DEFAULT_THREADS,
    delay: float = DEFAULT_THREADING_DELAY,
) -> dict[str:bool]:
    results = {}
    with ThreadPoolExecutor(max_threads) as executor:
        futures = {
            executor.submit(
                has_web_service, addresses[i], ports, timeout, (i + 1) * delay
            ): addresses[i]
            for i in range(len(addresses))
        }
        for future in as_completed(futures):
            ip, result = future.result()
            results[ip] = result
    return results


def get_cert_domain(
    ip: str, timeout: int = DEFAULT_WEB_TIMEOUT, delay: float = 0
) -> tuple[str, list[str]]:
    time.sleep(delay)
    context = ssl.create_default_context()
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                # Try SAN first
                alt_names = []
                for attr in cert.get("subjectAltName", []):
                    if attr[0] == "DNS":
                        alt_names.append(attr[1])
                return ip, alt_names
    except Exception as e:
        return ip, []


def get_cert_domain_threaded(
    ips: list[str],
    timeout: int = DEFAULT_WEB_TIMEOUT,
    max_threads: int = DEFAULT_THREADS,
    delay: float = DEFAULT_THREADING_DELAY,
) -> dict[str : list[str]]:
    results = {}
    with ThreadPoolExecutor(max_threads) as executor:
        futures = {
            executor.submit(
                get_cert_domain,
                ips[i],
                timeout,
                delay * (i + 1),
            ): ips[i]
            for i in range(len(ips))
        }
        for future in as_completed(futures):
            ip, domains = future.result()
            results[ip] = domains
    return results


def get_domain_keyword_set(domains: list[str]) -> set[str] | list:
    keywords = set()
    [[keywords.add(kw) for kw in domain.split(".")] for domain in domains]
    return keywords if len(keywords) > 0 else []


def filter_urls_by_keywords(urls: list[str], keywords: set[str]) -> set[str] | list:
    result = set(
        [
            result
            for result in urls
            if not any([keyword in keywords for keyword in result.split(".")])
        ]
    )
    return result if len(result) > 0 else []


def read_words(filepath: str, count: int = 100, at_random: bool = True) -> set[str]:
    words = set()
    with open(filepath, "r") as file:
        [words.add(word.strip()) for word in file.read().split("\n")]

    return list(words[:count] if not at_random else random.sample(sorted(words), min(count,len(words))))

def log(min_verbose_level: int, *message):
    global VERBOSE_LEVEL
    if VERBOSE_LEVEL >= min_verbose_level:
        print(*message)


def search_engine_scrape(
    search_engine_url: str,
    result_xpath: str,
    word: str,
    depth: int,
    next_page_xpath: str,
    init_delay: float = 0,
    delay: float = 0.5,
) -> tuple[str, list[str]]:
    """
    @Returns
        A tuple with the given word and a list of the unique urls that match the given xpath
    @Parameters
        str search_engine_url - the search engine with search param (e.g. google.com/search?q=, www.duckduckgo.com/?q=, https://bing.com/search?q=)
        str result_xpath - the xpath pattern that the results containing urls should match
        str word - search query content
        int depth - how many pages to walk
        str next_page_xpath - the template containing the next page url
        float init_delay - how long to wait before starting function
        float delay - how long to wait between requests
    """
    time.sleep(init_delay)
    options = Options()
    options.add_argument("--headless")  # run browser in background
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")

    # Launch browser
    driver = webdriver.Chrome(options=options)

    seen_urls = set()
    query_url = f"https://{search_engine_url}{word}"
    driver.get(query_url)

    for _ in range(depth):
        try:
            # Wait for results to load
            # wait.until(EC.presence_of_all_elements_located((By.XPATH, result_xpath)))
            results = driver.find_elements(By.XPATH, result_xpath)
            for r in results:
                href = r.get_attribute("href")
                if href:
                    seen_urls.add(
                        href.replace("https", "")
                        .replace("http", "")
                        .replace("www.", "")
                        .strip(".:/? ")
                    )

            # Find and click next page
            next_links = driver.find_elements(By.XPATH, next_page_xpath)
            if not next_links:
                break

            next_links[0].click()
            time.sleep(delay)  # Respectful delay between pages

        except Exception as e:
            print(f"[!] Error: {e}")
            break

    driver.quit()
    return word, list(seen_urls)

def dns_discovery(
          ips: list[str],
    dns_server: str,
    web_ports: list[str],
    alexa_csv_filepath: str,
    max_alexa_rank: int,
    timeout: int,
    threads: int,
    threading_delay: float,
    verbose_level: int = 1,
):
    global VERBOSE_LEVEL
    VERBOSE_LEVEL = verbose_level

    log(
        1,
        "Warning: DNS mode works for websites that are not virtually hosted and have a fully described SSL certificate. Use at your own risk",
    )

    log(
        1,
        f"Performing DNS queries at {dns_server} for {len(ips)} ip addresses using {threads} threads and delay of {threading_delay} seconds...",
    )
    # check if ips have a dns record
    dns_results = reverse_dns_threaded(ips, dns_server, threads, threading_delay)
    log(2, dns_results)
    # filter out unsuccessful checks
    dns_successful_results = {
        ip: result for ip, result in dns_results.items() if result != None
    }
    dns_successful_result_domains = set([url[:-1] for url in dns_successful_results.values()])
    log(1, f"Discovered {len(dns_successful_result_domains)} domains using DNS PTR records.")
    log(2, dns_successful_result_domains)
    log(
        1,
        f"Performing HTTP probes at ports {web_ports} for {len(dns_successful_results)} ip addresses using {threads} threads and delay of {threading_delay} seconds...",
    )
    # probe if addresses have http/s services
    http_results = has_web_service_threaded(
        list(dns_successful_results.keys()),
        web_ports,
        timeout,
        threads,
        threading_delay,
    )
    # filter out unsuccessful checks
    http_successful_results = [
        address for address in http_results.keys() if http_results[address]
    ]
    log(2, http_results)
    log(
        1,
        f"Performing SSL domain probes for {len(http_successful_results)} ip addresses using {threads} threads and delay of {threading_delay} seconds...",
    )
    # get domain names of addresses
    ssl_results = get_cert_domain_threaded(
        http_successful_results, timeout, threads, threading_delay
    )
    log(2, ssl_results)
    ssl_results_domains = set(
        [
            url.replace("*.", "")
            for domain_list in ssl_results.values()
            for url in domain_list
        ]
    )
    log(1, f"Discovered {len(ssl_results_domains)} domains using SSL certificates.")
    log(2, ssl_results_domains)

    # get alexa top domains
    log(1, f"Reading alexa top {max_alexa_rank} from {alexa_csv_filepath}...")
    alexa_top_domains = read_alexa_top_csv(alexa_csv_filepath, max_rank=max_alexa_rank)
    log(1, f"Extracting keywords from alexa top {len(alexa_top_domains)} domains...")
    alexa_kw = get_domain_keyword_set(alexa_top_domains)
    log(1, f"Extracted {len(alexa_kw)} keywords.")
    log(2, alexa_kw)

    # filter out top domains by keywords
    # using ssl
    log(1, f"Filtering discovered addresses using {len(alexa_kw)} kewords...")
    filtered_ssl_domains = filter_urls_by_keywords(ssl_results_domains, alexa_kw)
    log(
        1,
        f"Successfully selected {len(filtered_ssl_domains)} domains by SSL certificate.",
    )
    log(2, filtered_ssl_domains)
    # using dns
    log(1, f"Filtering discovered addresses using {len(alexa_kw)} kewords...")
    filtered_ptr_domains = filter_urls_by_keywords(dns_successful_result_domains, alexa_kw)
    log(
        1,
        f"Successfully selected {len(filtered_ptr_domains)} domains by DNS PTR record.",
    )
    log(2, filtered_ptr_domains)

    # merge results
    log(1, f"Merging results...")
    filtered_ips_total = set()
    [
        filtered_ips_total.add(ip)
        for ip in ssl_results.keys()
        if any([domain in ssl_results[ip] for domain in ssl_results_domains])
    ]
    [filtered_ips_total.add(ip) for ip in dns_results if dns_results[ip] != None]
    filtered_ips_total=list(filtered_ips_total)

    print(filtered_ips_total)
    return filtered_ips_total



def search_engine_scrape_threaded(
    search_engine_url: str,
    result_xpath: str,
    words: list[str],
    depth: int,
    next_page_xpath: str,
    max_threads: int = DEFAULT_THREADS,
    delay: float = DEFAULT_THREADING_DELAY,
) -> dict[str : list[str]]:
    results = {}
    with ThreadPoolExecutor(max_threads) as executor:
        futures = {
            executor.submit(
                search_engine_scrape,
                search_engine_url,
                result_xpath,
                words[i],
                depth,
                next_page_xpath,
                delay * (i + 1),
            ): words[i]
            for i in range(len(words))
        }
        for future in as_completed(futures):
            word, domains = future.result()
            results[word] = domains
    return results


def run(logger, options=None):
    logger.log("[*] Running discovery...")

    if options is None or "type" not in options:
        logger.log("[-] No discovery type specified. Exiting.")
        return []

    found_urls = []

    # === Search Engine Discovery ===
    if options["type"] == "search_engine":
        search_url = options.get("search_url")
        keywords_file = options.get("keywords_file")
        alexa_csv = options.get("alexa_csv")
        alexa_max_rank = int(options.get("alexa_max_rank"))
        xpath = options.get("xpath")
        depth = int(options.get("depth"))
        next_page_xpath = options.get("next_page_xpath")
        threads = int(options.get("threads"))
        delay = float(options.get("delay"))

        logger.log("Search Engine Discovery:")
        logger.log(f"    URL: {search_url}")
        logger.log(f"    Keywords File: {keywords_file}")
        logger.log(f"    XPath: {xpath}")
        logger.log(f"    Search depth: {depth}")
        logger.log(f"    Next page xpath: {next_page_xpath}")
        logger.log(f"    Threads: {threads}s")
        logger.log(f"    Delay: {delay}s")

        if options.get("output") != "json":
            raise NotImplementedError('Only supports JSON output')

        keywords = []
        alexa_top_sites = []
        try:
            keywords = read_words(keywords_file)
        except Exception as e:
            logger.log(f"[!] Failed to read keywords file: {e}")
            return []
        try:
            alexa_top_sites = read_alexa_top_csv(alexa_csv, max_rank=alexa_max_rank)
        except Exception as e:
            logger.log(f"[!] Failed to read alexa top domains file: {e}")
            return []

        scrape_results = search_engine_scrape_threaded(
            search_url, xpath, keywords, depth, next_page_xpath, threads, delay
        )
        alexa_kw = get_domain_keyword_set(alexa_top_sites)
        found_urls = [url for url_list in scrape_results.values() for url in url_list]
        found_urls = filter_urls_by_keywords(found_urls, alexa_kw)

        if not found_urls:
            logger.log("[!] No URLs found from search engine.")


    # === DNS Discovery ===
    elif options["type"] == "dns":
        ips = options.get("ips")
        dns_server = options.get("dns_server", "1.1.1.1")
        threads = int(options.get("threads", 20))
        ports = [int(p) for p in options.get("ports", "80,443").split(",")]
        timeout = int(options.get("timeout", 3))
        alexa_rank = int(options.get("alexa_rank", 100))
        alexa_file = options.get("alexa_file")
        delay = float(options.get("delay"))

        logger.log("DNS Discovery:")
        logger.log(f"    IPs: {ips}")
        logger.log(f"    DNS Server: {dns_server}")
        logger.log(f"    Ports: {ports}")
        logger.log(f"    Threads: {threads}")
        logger.log(f"    Timeout: {timeout}s")
        logger.log(f"    Alexa top sites CSV: {alexa_file}")
        logger.log(f"    Alexa Rank Limit: {alexa_rank}")

        alexa_top_sites = []
        try:
            alexa_top_sites = read_alexa_top_csv(alexa_file, max_rank=alexa_rank)
        except Exception as e:
            logger.log(f"[!] Failed to read alexa top domains file: {e}")
            return []

        # Simulated IP and port scan
        ips_addrs=[]
        if '/' in ips:
            addr,prefix = ips.split('/')
            ips_addrs=get_hosts_in_network(addr,prefix)
        elif '..' in ips:
            start,end = ips.split('..')
            ips_addrs=get_hosts_in_range(start,end)
        else:
            ips_addrs=ips.split(',')

        found_urls = dns_discovery(ips_addrs,dns_server,ports, alexa_file,alexa_rank,timeout,threads,delay)

        

    else:
        logger.log("[-] Unknown discovery type.")
        return []

    logger.log(f"[+] Discovered {len(found_urls)} URLs.")
    
    discovery_result = {'result':list(found_urls)}
    discovery_result.update(options)
    outpath=os.path.join('reports',f'discovery_{time.time()}.report.json')
    with open(outpath, 'w+') as output:
        output.write(json.dumps(discovery_result, indent=4))
        logger.log(f"Output saved to: {outpath}")

    return found_urls
