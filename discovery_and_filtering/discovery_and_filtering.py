import pandas as pd
import socket
import ipaddress


def read_alexa_top_csv(
    filepath: str = "top-1m.csv", min_rank=1, max_rank=100
) -> list[str]:
    df = pd.read_csv(filepath)
    return df["site"].to_list()[min_rank:max_rank]


def get_hosts_in_network(network: str) -> list[str]:
    network = ipaddress.ip_network(network)
    return [str(host) for host in network.hosts()]


def get_hosts_in_range(min_address: str, max_address: str) -> list[str]:
    min_address = ipaddress.ip_address(min_address)
    max_address = ipaddress.ip_address(max_address)
    return [
        str(ipaddress.ip_address(addr))
        for addr in range(int(min_address), int(max_address) + 1)
    ]


def get_hostname_by_ip(
    ip_start: str, ip_end: str = None, prefix: int = None
) -> None | str | list[str | None]:
    # validate ip addr given

    if not ip_end and not prefix:
        try:
            hostname = socket.gethostbyaddr(ip_start)[0]
            print(ip_start, ":", hostname)
            return hostname
        except socket.herror:
            print("could not resolve host", ip_start)
            return None

    hosts = []
    if ip_end:
        hosts = get_hosts_in_range(ip_start, ip_end)
    elif prefix:
        hosts = get_hosts_in_network(ip_start + "/" + str(prefix))

    # TODO: use threading
    return [get_hostname_by_ip(str(host)) for host in hosts]


if __name__ == "__main__":
    print(get_hostname_by_ip("2a06:98c0::",prefix=29))
