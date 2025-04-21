import os
import time
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.alert import Alert
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException

def run_selenium_test(url, logger, results=None):
    if results is None:
        results = []

    logger.log(f"[Selenium] Opening browser for URL: {url}")

    # Set Chrome options
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--log-level=3")  # Suppress logs

    driver = webdriver.Chrome(options=options)

    try:
        driver.get(url)
        time.sleep(2)

        # ✅ Save screenshot
        os.makedirs("reports", exist_ok=True)
        parsed = urlparse(url)
        safe_name = parsed.netloc.replace(".", "_") + "_" + str(int(time.time()))
        screenshot_path = f"reports/{safe_name}.png"
        driver.save_screenshot(screenshot_path)
        logger.log(f"[Selenium] Screenshot saved: {screenshot_path}")

        # ✅ Try to handle alert if triggered
        try:
            alert = Alert(driver)
            alert_text = alert.text
            logger.log(f"[Selenium] Alert detected: {alert_text}")
            alert.accept()
            logger.log("[Selenium] Alert accepted. Stored XSS likely triggered!")

            results.append({
                "url": url,
                "param": "n/a",
                "payload": "stored-payload",
                "type": "stored_xss",
                "screenshot": screenshot_path
            })

        except NoAlertPresentException:
            logger.log("[Selenium] No alert popup present.")

        # ✅ Fallback check in page source
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


def run(logger):
    return None