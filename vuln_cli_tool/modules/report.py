import json
import csv
import os
from datetime import datetime

def save_report(results, output_format='json'):
    """
    Save scan results to a file in JSON or CSV format.
    Adds a timestamp to each report filename to avoid overwriting.
    """
    output_dir = 'reports'
    os.makedirs(output_dir, exist_ok=True)

    if not results:
        print("[!] No results to save.")
        return

    # Generate a timestamped filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename_base = f"xss_scan_report_{timestamp}"

    if output_format == 'json':
        output_file = os.path.join(output_dir, f"{filename_base}.json")
        with open(output_file, 'w', encoding='utf-8') as json_file:
            json.dump(results, json_file, indent=4, ensure_ascii=False)
        print(f"[+] Report saved in JSON format: {output_file}")

    elif output_format == 'csv':
        output_file = os.path.join(output_dir, f"{filename_base}.csv")
        fieldnames = ["url", "param", "payload", "type"]
        with open(output_file, 'w', newline='', encoding='utf-8') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            for result in results:
                writer.writerow({
                    "url": result.get("url", ""),
                    "param": result.get("param", ""),
                    "payload": result.get("payload", ""),
                    "type": result.get("type", "")
                })
        print(f"[+] Report saved in CSV format: {output_file}")

    else:
        print("[!] Unsupported format. Please choose 'json' or 'csv'.")
