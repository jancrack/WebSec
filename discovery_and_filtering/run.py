import modules.discovery_and_filtering as df

TEST_IPS = [
    "23.227.38.65",
    "195.191.149.84",  # restaurant-india.com
    "216.58.214.142",  # google.com ipv4
    "2a00:1450:4017:816::200e",  # google.com ipv6
    "192.0.2.1",  # internal ip (no dns record)
    "8.8.8.8",  # ip with dns record (no web service)
    "1.1.1.1",  # ip with dns record (no web service)
]
TEST_DNS = "1.1.1.1"
TEST_THREADS = 20
TEST_PORTS = [80, 443, 8080, 8000, 8008, 8888]
TEST_TIMEOUT = 1
TEST_ALEXA_MAX_RANK = 1000000
TEST_ALEXA_CSV = "top-1m.csv"
TEST_DELAY = 0.5
TEST_SEARCH_ENGINE = "duckduckgo.com/?q="
TEST_RESULT_XPATH = "//*/div/h2/a"
TEST_NEXT_PAGE_XPATH = '//*[@id="more-results"]'
TEST_SEARCH_DEPTH = 5
TEST_SEARCH_PHRASES = ["test", "google.com"]


def log(min_verbose_level: int, *message):
    global VERBOSE_LEVEL
    if VERBOSE_LEVEL >= min_verbose_level:
        print(*message)


def dns(
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
    dns_results = df.reverse_dns_threaded(ips, dns_server, threads, threading_delay)
    log(2, dns_results)
    # filter out unsuccessful checks
    dns_successful_results = {
        ip: result for ip, result in dns_results.items() if result != None
    }
    dns_successful_urls = set([url[:-1] for url in dns_successful_results.values()])
    log(1, f"Discovered {len(dns_successful_urls)} domains using DNS PTR records.")
    log(2, dns_successful_urls)
    log(
        1,
        f"Performing HTTP probes at ports {web_ports} for {len(dns_successful_results)} ip addresses using {threads} threads and delay of {threading_delay} seconds...",
    )
    # probe if addresses have http/s services
    http_results = df.has_web_service_threaded(
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
    ssl_results = df.get_cert_domain_threaded(
        http_successful_results, timeout, threads, threading_delay
    )
    log(2, ssl_results)
    ssl_domains = set(
        [
            url.replace("*.", "")
            for domain_list in ssl_results.values()
            for url in domain_list
        ]
    )
    log(1, f"Discovered {len(ssl_domains)} domains using SSL certificates.")
    log(2, ssl_domains)

    # get alexa top domains
    log(1, f"Reading alexa top {max_alexa_rank} from {alexa_csv_filepath}...")
    alexa_top = df.read_alexa_top_csv(alexa_csv_filepath, max_rank=max_alexa_rank)
    log(1, f"Extracting keywords from alexa top {len(alexa_top)} domains...")
    keywords = df.get_domain_keyword_set(alexa_top)
    log(1, f"Extracted {len(keywords)} keywords.")
    log(2, keywords)

    # filter out top domains by keywords
    # using ssl
    log(1, f"Filtering discovered addresses using {len(keywords)} kewords...")
    filtered_ssl_domains = df.filter_urls_by_keywords(ssl_domains, keywords)
    log(
        1,
        f"Successfully selected {len(filtered_ssl_domains)} domains by SSL certificate.",
    )
    log(2, filtered_ssl_domains)
    # using dns
    log(1, f"Filtering discovered addresses using {len(keywords)} kewords...")
    filtered_ptr_domains = df.filter_urls_by_keywords(dns_successful_urls, keywords)
    log(
        1,
        f"Successfully selected {len(filtered_ptr_domains)} domains by DNS PTR record.",
    )
    log(2, filtered_ptr_domains)


def search(
    search_engine: str,
    result_xpath: str,
    search_phrases: list[str],
    search_depth: int,
    next_page_xpath: str,
    alexa_csv_filepath: str,
    alexa_max_rank: int,
    max_threads: int,
    thread_delay: float,
    verbose_level:int
):
    global VERBOSE_LEVEL
    VERBOSE_LEVEL = verbose_level

    log(1, f'Scraping search engine {search_engine} with {len(search_phrases)} search phrases using {max_threads} threads with {thread_delay}s delay...')
    results = df.search_engine_scrape_threaded(
        search_engine,
        result_xpath,
        search_phrases,
        search_depth,
        next_page_xpath,
        max_threads,
        thread_delay,
    )
    log(2, results)
    urls = [url for urls in results.values() for url in urls]
    log(1, f'Extracted {len(urls)} urls.')
    log(2, urls)

    log(1, f'Reading top alexa {alexa_max_rank} ranked sites...')
    alexa_1m = df.read_alexa_top_csv(alexa_csv_filepath, max_rank=alexa_max_rank)
    alexa_kw = df.get_domain_keyword_set(alexa_1m)
    log(1, f'Extracted {len(alexa_kw)} keywords for filtration.')
    log(2, alexa_kw)

    log(1, f'Filtering {len(urls)} urls using {len(alexa_kw)} keywords...')
    filtered_urls = df.filter_urls_by_keywords(urls, alexa_kw)

    log(1, f'Extracted {len(filtered_urls)} urls.')
    print(filtered_urls)


if __name__ == "__main__":
    # dns(
    #     TEST_IPS,
    #     TEST_DNS,
    #     TEST_PORTS,
    #     TEST_ALEXA_CSV,
    #     TEST_ALEXA_MAX_RANK,
    #     TEST_TIMEOUT,
    #     TEST_THREADS,
    #     TEST_DELAY,
    #     verbose_level=2,
    # )
    search(
        TEST_SEARCH_ENGINE,
        TEST_RESULT_XPATH,
        TEST_SEARCH_PHRASES,
        TEST_SEARCH_DEPTH,
        TEST_NEXT_PAGE_XPATH,
        TEST_ALEXA_CSV,
        TEST_ALEXA_MAX_RANK,
        TEST_THREADS,
        TEST_DELAY,
        verbose_level=1,
    )
