import modules.discovery_and_filtering as df

TEST_IPS = [
    "216.58.214.142",  # google.com ipv4
    "2a00:1450:4017:816::200e",  # google.com ipv6
    "192.0.2.1",  # internal ip (no dns record)
    "8.8.8.8",  # ip with dns record (no web service)
    "1.1.1.1",  # ip with dns record (no web service)
]
TEST_DNS = "1.1.1.1"
TEST_THREADS = 20
TEST_PORTS = [80, 8080, 443]
TEST_TIMEOUT = 1


def main(
    ips: list[str],
    dns_server: str,
    web_ports: list[str],
    timeout: int,
    threads: int,
    verbose_level: int = 1,
):
    if verbose_level >= 1:
        print(
            f"Performing DNS queries at {dns_server} for {len(ips)} ip addresses using {threads} threads..."
        )
    # check if ips have a dns record
    dns_results = df.reverse_dns_threaded(
        ips,
        dns_server,
        threads,
    )
    # filter out unsuccessful checks
    dns_successful_results = {
        ip: result for ip, result in dns_results.items() if result != None
    }
    if verbose_level >= 2:
        print(dns_results)

    if verbose_level >= 1:
        print(
            f"Performing HTTP probes at ports {web_ports} for {len(dns_successful_results)} ip addresses using {threads} threads..."
        )
    # probe if addresses have http/s services
    http_results = df.has_web_service_threaded(
        dns_successful_results.keys(), web_ports, timeout, threads
    )
    # filter out unsuccessful checks
    http_successful_results = [
        address for address in http_results.keys() if http_results[address]
    ]
    if verbose_level >= 2:
        print(http_results)

    if verbose_level >= 1:
        print(
            f"Performing SSL domain probes for {len(http_successful_results)} ip addresses using {threads} threads..."
        )
    # get domain names of addresses
    domain_results = df.get_cert_domain_threaded(
        http_successful_results, web_ports, timeout, threads
    )
    if verbose_level >= 2:
        print(domain_results)

    # print(domain_results)


if __name__ == "__main__":
    main(TEST_IPS, TEST_DNS, TEST_PORTS, TEST_TIMEOUT, TEST_THREADS, verbose_level=100)
