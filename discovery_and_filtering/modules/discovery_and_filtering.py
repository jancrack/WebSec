import ssl
import socket
import ipaddress
import dns.resolver
import pandas as pd
import dns.reversename
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_DNS_SERVER: str = "8.8.8.8"
DEFAULT_WEB_TIMEOUT: int = 3
DEFAULT_WEB_PORTS: list[int] = [80, 8080, 443]
DEFAULT_THREADS: int = 20


def read_alexa_top_csv(
    filepath: str = "top-1m.csv",
    min_rank: int = 1,
    max_rank: int = 100,
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
    ip: str, dns_server: str = DEFAULT_DNS_SERVER
) -> tuple[str, str | None]:
    """
    @Returns
        A tuple of the given ip and the result from the DNS query or None
    @Parameters
        str ip - address of the target
        str dns_server - ip address of the dns server
    """
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
        futures = {executor.submit(reverse_dns, ip, dns_server): ip for ip in ips}
        for future in as_completed(futures):
            ip, domain = future.result()
            results[ip] = domain
    return results


def has_web_service(
    ip: str, ports: list[int] = DEFAULT_WEB_PORTS, timeout: int = DEFAULT_WEB_TIMEOUT
) -> tuple[str, bool]:
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
) -> dict[str:bool]:
    results = {}
    with ThreadPoolExecutor(max_threads) as executor:
        futures = {
            executor.submit(has_web_service, address, ports, timeout): address
            for address in addresses
        }
        for future in as_completed(futures):
            ip, result = future.result()
            results[ip] = result
    return results


def get_cert_domain(
    ip: str, port: int, timeout: int = DEFAULT_WEB_TIMEOUT
) -> tuple[str, list[str]]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
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
    ports:list[int],
    timeout: int = DEFAULT_WEB_TIMEOUT,
    max_threads: int = DEFAULT_THREADS,
) -> dict[str : list[str]]:
    results = {}
    ipAtPort = list(zip(ips, ports))
    with ThreadPoolExecutor(max_threads) as executor:
        futures = {
            executor.submit(get_cert_domain, ip, port, timeout): ip
            for ip, port in ipAtPort
        }
        for future in as_completed(futures):
            ip, domains = future.result()
            results[ip] = domains
    return results
