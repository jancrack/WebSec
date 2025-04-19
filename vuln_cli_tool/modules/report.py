import json
import csv
import os


def save_report(results, output_format='json'):
    """
    Save results to a file in the specified format: JSON or CSV.
    """
    # Define the output file name (use a timestamp to avoid overwriting)
    output_dir = 'reports'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    if output_format == 'json':
        output_file = os.path.join(output_dir, 'xss_scan_report.json')
        with open(output_file, 'w') as json_file:
            json.dump(results, json_file, indent=4)
        print(f"Report saved in JSON format: {output_file}")

    elif output_format == 'csv':
        output_file = os.path.join(output_dir, 'xss_scan_report.csv')
        with open(output_file, 'w', newline='') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=["url", "param", "payload", "type"])
            writer.writeheader()
            for result in results:
                writer.writerow(result)
        print(f"Report saved in CSV format: {output_file}")

    else:
        print("[!] Unsupported format. Please choose 'json' or 'csv'.")
