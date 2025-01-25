from dotenv import load_dotenv
import os
import requests
import logging
from DNS_Cache_Monitor import DNS_Access

def get_api():
    load_dotenv()
    API_KEY = os.getenv("API_KEY")
    return API_KEY


def IP_Lookup(api, ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
    "accept": "application/json",
    "x-apikey": f"{api}"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None
'''
Filter the virustotal json into containing only sources that view the ip as malicious,
along with their respective data
'''
def IP_Filter(data):
    sources = []
    if data is not None:
        for source, details in data["data"]["attributes"]["last_analysis_results"].items():
            if details["result"] == "malicious" or details["result"] == "malware":
                sources.append(source)
        if len(sources) == 0:
            return None
        else:
            return sources, data["data"]["attributes"]["whois"]
    return None
    

def create_logger():
    malicious_logger = logging.getLogger("malicious_ips")
    malicious_handler = logging.FileHandler("malicious_ips.log", delay=False)
    malicious_handler.setLevel(logging.WARNING)
    malicious_formatter = logging.Formatter("%(asctime)s\n%(message)s")
    malicious_handler.setFormatter(malicious_formatter)
    malicious_logger.addHandler(malicious_handler)
    malicious_logger.propagate = False
    return malicious_logger
def log_flaggedIP(logger, ip, sources, extra_data):
    logger.warning(f"Flagged IP: {ip}\nSources: {sources}\n{extra_data}")

def job():
    ips = DNS_Access.read_dns_cache()
    logger = create_logger()
    for ip in ips:
        result = IP_Filter(IP_Lookup(get_api(), ip))
        if result is not None:
            log_flaggedIP(logger, ip, result[0], result[1])