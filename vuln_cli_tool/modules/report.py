import json
import csv

results = []


def add_result(result):
    results.append(result)


def export(formats='json'):
    if formats == 'json':
        with open('reports/report.json', 'w') as f:
            json.dump(results, f, indent=2)
    elif formats == 'csv':
        with open('reports/report.csv', 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
