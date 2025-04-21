import ssl
import html
import time
import socket
import random
import requests
import ipaddress
import dns.resolver
import pandas as pd
from lxml import html
import dns.reversename
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_DNS_SERVER: str = "8.8.8.8"
DEFAULT_WEB_TIMEOUT: int = 3
DEFAULT_WEB_PORTS: list[int] = [80, 8080, 8008, 8000, 8888, 443]
DEFAULT_THREADS: int = 20
DEFAULT_SEARCH_ENGINE_PORT: int = 80
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
    df = pd.read_csv(filepath)
    word_list = df[0].to_list()
    return random.sample(word_list, count) if at_random else word_list[:count]


def search_engine_scrape(
    search_engine_url: str,
    result_xpath: str,
    word: str,
    depth: int,
    next_page_xpath: str,
    search_engine_port: int = DEFAULT_SEARCH_ENGINE_PORT,
    init_delay: float = 0,
    delay: float = 0,
) -> tuple[str, list[str]]:
    """
    @Returns
        A tuple with the given word and a list of the unique urls that match the given xpath
    @Parameters
        str search_engine_url - the search engine (e.g. google.com, www.yahoo.com, https://bing.com)
        str result_xpath - the xpath pattern that the results containing urls should match
        str word - search query content
        int depth - how many pages to walk
        str next_page_xpath - the template containing the next page url
        int search_engine_port - the port of the search engine http/s protocol
        float init_delay - how long to wait before starting function
        float delay - how long to wait between requests
    """
    seen_urls = set()
    current_url = f"https://{search_engine_url}:{search_engine_port}/search?q={word}"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
    }
    time.sleep(init_delay)
    for _ in range(depth):
        try:
            response = requests.get(current_url, headers=headers, timeout=10)
            if response.status_code != 200:
                break

            tree = html.fromstring(response.content)

            # extract result urls
            urls = tree.xpath(result_xpath)
            clean_urls = [url.strip() for url in urls if url.strip()]
            seen_urls.update(clean_urls)

            # get next page url
            next_page_links = tree.xpath(next_page_xpath)
            if not next_page_links:
                break

            next_page_url = urljoin(current_url, next_page_links[0])
            current_url = next_page_url

            time.sleep(delay)

        except Exception as e:
            print(f"Error fetching or parsing page: {e}")
            break

    return word, list(seen_urls)


def search_engine_scrape_threaded(
    search_engine_url: str,
    result_xpath: str,
    words: list[str],
    depth: int,
    search_engine_port: int = DEFAULT_SEARCH_ENGINE_PORT,
) -> dict[str : list[str]]:
    pass
