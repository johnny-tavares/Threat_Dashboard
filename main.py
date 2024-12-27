from dotenv import load_dotenv
import os
import requests
import logging
import DNS_Access
import schedule
import sys
import time

load_dotenv()
API_KEY = os.getenv("API_KEY")

#Lookup an IP on the virustotal database
def IP_Lookup(api, ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
    "accept": "application/json",
    "x-apikey": f"{api}"
    }
    response = requests.get(url, headers=headers)
    return response.json()
'''
Filter the virustotal json into containing only sources that view the ip as malicious,
along with their respective data
'''
def IP_Filter(data):
    sources = []
    for source, details in data["data"]["attributes"]["last_analysis_results"].items():
        if details["result"] == "malicious" or details["result"] == "malware":
            sources.append(source)
    if len(sources) == 0:
        return None
    else:
        return sources, data["data"]["attributes"]["whois"]
#Create a logger for malicious ip's
malicious_logger = logging.getLogger("malicious_ips")
malicious_handler = logging.FileHandler("malicious_ips.log")
malicious_handler.setLevel(logging.WARNING)
malicious_formatter = logging.Formatter("%(asctime)s - %(message)s")
malicious_handler.setFormatter(malicious_formatter)
malicious_logger.addHandler(malicious_handler)
def log_flaggedIP(ip, sources, extra_data):
    malicious_logger.warning(f"Flagged IP: {ip} - Sources: {sources}\nExtra 'whois' data:\n{extra_data}")

def job():
    ips = DNS_Access.read_dns_cache()
    for ip in ips:
        print(f"Checking ip: {ip}")
        result = IP_Filter(IP_Lookup(API_KEY, ip))
        if result is not None:
            log_flaggedIP(ip, result[0], result[1])

job()
mins = int(sys.argv[1])
s = schedule.every(mins).minutes.do(job)
while True:
    schedule.run_pending()
    time.sleep(1) 

