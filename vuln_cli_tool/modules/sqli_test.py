import subprocess

def run(logger,sqlmap_path, target_urls=None):
    """
    Run SQL injection test using sqlmap on a list of URLs.
    """
    results = []

    if target_urls is None:
        # Default test target
        logger.log('[-] No urls given, exiting')
        return []
    

    for url in target_urls:
        logger.log(f"[+] Starting scan on {url} using sqlmap...")

        try:
            command = [
                'python', sqlmap_path,
                '-u', url,
                '--batch',
                '--risk=3',
                '--level=5',
                '--random-agent'
            ]

            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8')

            vulnerable = False

            for line in process.stdout:
                logger.log(line.strip())
                if "is vulnerable" in line.lower() or "sql injection" in line.lower():
                    vulnerable = True

            process.wait()

            if vulnerable:
                logger.log("[!] SQL Injection vulnerability found!")
                results.append({
                    "url": url,
                    "param": "cat",
                    "payload": "sqlmap",
                    "type": "sqli"
                })
            else:
                logger.log("[+] No SQLi vulnerabilities detected.")

        except Exception as e:
            logger.log(f"[!] Error running sqlmap: {e}")

    return results
