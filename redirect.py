import requests
import sys
import time
import os
import argparse

# Color codes
YELLOW = '\033[93m'
GREEN = '\033[92m'
RED = '\033[91m'
ENDC = '\033[0m'

def clear_screen():
    os.system('clear')

def print_banner():
    clear_screen()
    print("#################################################")
    print("# Open redirect Scanner for ScriptKiddies like me :)  #")
    print("#  by archtrmntor (archtrmntor@proton.me)       #")
    print("#  twitter.com/Archtrmntor                      #")
    print("#  Linkedin Username :- Archtrmntor             #")
    print("#################################################")
    print("")
    print("Usage: ./redirect.py [options]")
    print("")
    print("         ./redirect.py -u http://example.com -p payloads.txt -o output.txt")
    print("")
    print("Color coding:")
    print("    - Testing message: " + YELLOW + "Yellow" + ENDC)
    print("    - Redirected status code 301: " + GREEN + "Green" + ENDC)
    print("    - Other error status codes: " + RED + "Red" + ENDC)
    print("")
    print("For extracting the final 301 redirect successful attempt, use the following command:")
    print("cat output_filename.txt | grep -e '+ 301' -e 'Final destination'")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Open Redirect Scanner")
    parser.add_argument("-f", "--file", help="File containing subdomains")
    parser.add_argument("-u", "--url", help="URL to scan for open redirect vulnerability")
    parser.add_argument("-p", "--payloads", help="File containing list of payloads", required=True)
    parser.add_argument("-o", "--output", help="Output file to save results")
    return parser.parse_args()

def load_payloads(payloads_file):
    with open(payloads_file) as f:
        return f.readlines()

def colorize_response(response):
    status_code = response.status_code
    if status_code == 301:
        return GREEN + str(status_code) + ENDC
    elif status_code >= 400 and status_code < 500:
        return RED + str(status_code) + ENDC
    else:
        return str(status_code)

def save_output(output_file, message):
    with open(output_file, "a") as f:
        f.write(message + "\n")

def scan_redirects(subdomains_file, payloads, output_file):
    with open(subdomains_file) as f:
        print("")
        print("Searching for open redirect vulnerabilities...")
        print("")
        time.sleep(2)
        for line in f:
            line = line.strip()
            for payload in payloads:
                try:
                    url = 'http://' + line + RED + payload.strip() + ENDC
                    print(YELLOW + "Testing: " + url + ENDC)
                    response = requests.get(url, verify=True)
                    if response.history:
                        message = "Request was redirected\n"
                        for resp in response.history:
                            message += "| " + colorize_response(resp) + " " + resp.url + "\n"
                        message += "Final destination:\n+ " + colorize_response(response) + " " + response.url
                        print(message)
                    else:
                        print("Request was not redirected")
                    if output_file:
                        save_output(output_file, url)
                        save_output(output_file, message)
                except Exception as e:
                    print("Error occurred:", str(e))
            print("\n" + "-"*50 + "\n")

def scan_redirects_single_url(url, payloads, output_file):
    print("")
    print("Searching for open redirect vulnerabilities...")
    print("")
    time.sleep(2)
    for payload in payloads:
        try:
            url_with_payload = url + RED + payload.strip() + ENDC
            print(YELLOW + "Testing: " + url_with_payload + ENDC)
            response = requests.get(url_with_payload, verify=True)
            if response.history:
                message = "Request was redirected\n"
                for resp in response.history:
                    message += "| " + colorize_response(resp) + " " + resp.url + "\n"
                message += "Final destination:\n+ " + colorize_response(response) + " " + response.url
                print(message)
            else:
                print("Request was not redirected")
            if output_file:
                save_output(output_file, url_with_payload)
                save_output(output_file, message)
        except Exception as e:
            print("Error occurred:", str(e))
        print("\n" + "-"*50 + "\n")

def main():
    print_banner()
    args = parse_arguments()
    payloads_file = args.payloads
    payloads = load_payloads(payloads_file)
    output_file = args.output
    if args.file:
        subdomains_file = args.file
        scan_redirects(subdomains_file, payloads, output_file)
    elif args.url:
        url = args.url
        scan_redirects_single_url(url, payloads, output_file)
    else:
        print("Please provide either a file containing subdomains (-f) or a single URL (-u).")

if __name__ == "__main__":
    main()

print("For extracting the final 301 redirect successful attempt, use the following command:")
print("cat output_filename.txt | grep -e '+ 301' -e 'Final destination'")
