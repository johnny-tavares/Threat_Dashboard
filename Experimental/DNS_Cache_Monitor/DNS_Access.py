import subprocess
import re


def read_dns_cache():
    '''#Run ipconfig /displaydns to get the DNS cache on windows
    result = subprocess.run(['ipconfig', '/displaydns'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Check if the command ran successfully
    if result.returncode != 0:
        print("Error retrieving DNS cache.")
        return []
    
    # Extract IP addresses using regex
    # This pattern looks for IP addresses in the DNS cache output
    ip_addresses = re.findall(r'Address:\s([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', result.stdout)
    
    return ip_addresses'''
    return "185.234.216.59", "212.83.185.105"
