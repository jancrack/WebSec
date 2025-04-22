import os
import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.alert import Alert
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException

# List of basic XSS payloads to test with
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "'\"><img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>"
]

# Run a Selenium test to detect stored or DOM-based XSS
def run_selenium_test(url, logger, results):
    logger.log(f"[Selenium] Opening browser for URL: {url}")

    # Configure Chrome for headless execution
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--log-level=3")

    driver = webdriver.Chrome(options=options)

    try:
        driver.get(url)
        time.sleep(3)  

        # Save a screenshot of the page
        os.makedirs("reports", exist_ok=True)
        parsed = urlparse(url)
        safe_name = parsed.netloc.replace(".", "_") + "_" + str(int(time.time()))
        screenshot_path = f"reports/{safe_name}.png"
        driver.save_screenshot(screenshot_path)
        logger.log(f"[Selenium] Screenshot saved: {screenshot_path}")

        # Try to handle any alert triggered by payloads
        try:
            alert = Alert(driver)
            alert_text = alert.text
            logger.log(f"[Selenium] Alert detected: {alert_text}")
            alert.accept()
            logger.log("[Selenium] Alert accepted. Stored XSS likely triggered.")

            results.append({
                "url": url,
                "param": "n/a",
                "payload": "stored-payload",
                "type": "stored_xss",
                "screenshot": screenshot_path
            })

        except NoAlertPresentException:
            logger.log("[Selenium] No alert popup present.")

        # Check page source for presence of script tags or alert text
        if "alert" in driver.page_source or "<script>" in driver.page_source:
            logger.log("[!] Potential stored XSS found in page source.")
            results.append({
                "url": url,
                "param": "n/a",
                "payload": "stored-payload",
                "type": "stored_xss_fallback",
                "screenshot": screenshot_path
            })

    except UnexpectedAlertPresentException as e:
        logger.log(f"[!] Unexpected alert crashed the session: {e}")
        try:
            alert = Alert(driver)
            alert.accept()
            logger.log("[Selenium] Crash alert handled.")
        except Exception as inner_e:
            logger.log(f"[Selenium] Failed to handle crash alert: {inner_e}")

    except Exception as e:
        logger.log(f"[!] Selenium error: {e}")

    finally:
        driver.quit()

# Inject payloads into each parameter of the URL and scan for reflected XSS
def inject_payloads(url, logger, results):
    logger.log(f"[*] Scanning URL: {url}")
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    # Skip URLs without parameters
    if not qs:
        logger.log(f"[-] No parameters found in URL: {url}")
        return

    for param in qs:
        for payload in XSS_PAYLOADS:
            test_params = qs.copy()
            test_params[param] = [payload]
            encoded_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, encoded_query, parsed.fragment))

            logger.log(f"[+] Testing param '{param}' with payload: {payload}")

            try:
                response = requests.get(test_url, timeout=5)
                if payload in response.text and "&lt;" not in response.text:
                    logger.log(f"[!] Reflected XSS found on param '{param}'")
                    results.append({
                        "url": test_url,
                        "param": param,
                        "payload": payload,
                        "type": "reflected"
                    })

                # Run stored/DOM XSS check with Selenium
                run_selenium_test(test_url, logger, results)

            except Exception as e:
                logger.log(f"[!] Request failed: {e}")

# Entry point for this module
def run(logger, options, target_urls=None):
    results = []

    # Default URLs to scan if none provided
    if target_urls is None:
        target_urls = [
            options.get('url')
        ]

    logger.log("[*] Starting XSS scan...")

    for url in target_urls:
        inject_payloads(url, logger, results)

    logger.log(f"[+] XSS scan complete. {len(results)} issues found.")
    return results
