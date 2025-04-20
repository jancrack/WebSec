import subprocess
import sys

def test_sql_injection(url):
    try:
        print(f"[+] Стартира се сканиране на {url} със sqlmap...\n")

        sqlmap_path = 'D:\\WebSec\\sqlmap-master\\sqlmap.py'

        command = [
            'python', sqlmap_path,
            '-u', url,
            '--batch',
            '--risk=3',
            '--level=5',
            '--random-agent'
        ]

        # Стартираме процеса с Popen, за да следим stdout в реално време
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        vulnerable = False

        for line in process.stdout:
            print(line, end='')  # извеждаме редовете както пристигат

            if "is vulnerable" in line.lower():
                vulnerable = True

        process.wait()

        if vulnerable:
            print("[!] Възможна SQL инжекция открита!")
        else:
            print("[+] Не бяха открити уязвимости.")

    except Exception as e:
        print(f"[!] Възникна грешка: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Използване: python script.py <url>")
        sys.exit(1)

    target_url = sys.argv[1]
    test_sql_injection(target_url)
