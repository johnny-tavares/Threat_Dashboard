import psutil
import logging
import hashlib
import requests
import os
from dotenv import load_dotenv
import subprocess
import glob

def create_logger():
    suspicious_logger = logging.getLogger("suspicious_processes")
    suspicious_logger.setLevel(logging.WARNING)
    
    handler = logging.FileHandler("suspicious_processes.log", delay=False)
    formatter = logging.Formatter("%(asctime)s\n%(message)s")
    handler.setFormatter(formatter)

    suspicious_logger.addHandler(handler)
    
    suspicious_logger.propagate = False  

    return suspicious_logger

def is_signed_by_windows(exe_path):
    try:
        # Run PowerShell to get the signature status of the process
        result = subprocess.run(["powershell", "-Command", f"Get-AuthenticodeSignature '{exe_path}'"],
                                capture_output=True, text=True)
        # Check if the signature is valid
        if "Valid" in result.stdout:
            return True
        else:
            return False
    except Exception:
        return False

def is_signed_by_apple(exe_path):
    try:
        output = subprocess.check_output(['codesign', '--verify', '--verbose', exe_path], stderr=subprocess.STDOUT)
        decoded_output = output.decode()

        # Check for specific success criteria in the output
        if "satisfies its Designated Requirement" in decoded_output:
            return True  # The signature is valid and satisfies its requirements
        return False
    except subprocess.CalledProcessError:
        return False

def get_process_paths(os, smart):
    processes = {}
    for process in psutil.process_iter(['pid', 'name']):
        try:
            proc = psutil.Process(process.info['pid'])
            exe_path = proc.exe()
            if smart:
                if os == "m":
                    if not is_signed_by_apple(exe_path):
                        processes.update({process.info['name']: exe_path})
                if os == "w":
                    if not is_signed_by_windows(exe_path):
                        print(process.info['name'], exe_path)
                        processes.update({process.info['name']: exe_path})
            else:
                processes.update({process.info['name']: exe_path})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return processes

def get_windows_startups():
    startup_folder = os.path.join(os.getenv('APPDATA'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup')

    return glob.glob(os.path.join(startup_folder, "*"))

def get_launch_agents_daemons():
    filepaths = []
    # Directories to check for launch agents and daemons
    directories = [
        '/Library/LaunchAgents',
        '/Library/LaunchDaemons',
        os.path.expanduser('~/Library/LaunchAgents'),
        '/System/Library/LaunchDaemons'
    ]
    # Iterate over directories and gather file paths
    for directory in directories:
        if os.path.exists(directory):
            for root, _, files in os.walk(directory):
                for file in files:
                    if "com.apple" not in os.path.join(root, file):
                        filepaths.append(os.path.join(root, file))
    return filepaths

def get_file_hash(filepath):
    try:
        with open(filepath, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        return file_hash
    except Exception as e:
        print(f"Error reading file {filepath}: {e}")
        return None

load_dotenv()
API_KEY = os.getenv("API_KEY")

def virustotal_query(hash, logger, process, path):
    url = f"https://www.virustotal.com/api/v3/files/{hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": f"{API_KEY}"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        json = response.json()
        #Filter the json for malicious detection
        attributes = json["data"]["attributes"]
        malicious_flags = attributes["last_analysis_stats"]["malicious"]

        #Potential Yara data could be useful
        yara_data = None
        if "crowdsourced_yara_results" in attributes and attributes["crowdsourced_yara_results"]:
            yara_data = attributes["crowdsourced_yara_results"][0]
        #Potential AI analysis could be useful
        AI_Analysis = None
        if "crowdsourced_ai_results" in attributes and attributes["crowdsourced_ai_results"]:
            AI_Analysis = attributes["crowdsourced_ai_results"][0]["analysis"]
        
        if malicious_flags > 0:
            logger.warning(f"Flagged process: {process} - File path: {path} - Number of sources: {malicious_flags}\nHash: {hash}\nYara results: {yara_data}\nAI analysis: {AI_Analysis}\n")    

def collect(os, smart):
    processes = get_process_paths(os, smart)
    logger = create_logger()
    for process, path in processes.items():
        hash = get_file_hash(path)
        if hash:
            virustotal_query(hash, logger, process, path)
    if os == "m":
        launch_daemons = get_launch_agents_daemons()
        for path in launch_daemons:
            hash = get_file_hash(path)
            virustotal_query(hash, logger, "Launch Daemon", path)
    if os == "w":
        startup_files = get_windows_startups()
        for path in startup_files:
            hash = get_file_hash(path)
            virustotal_query(hash, logger, "Startup process", path)
    

def job(os, smart):
    collect(os, smart)