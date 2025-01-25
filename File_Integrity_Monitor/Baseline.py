import sys
import json
import os
import hashlib

BASELINE_FILE = "baselines.json"

def load_baselines():
    if os.path.basename(os.getcwd()) == "File_Integrity_Monitor":
        parent_directory = os.path.dirname(os.getcwd())
        baseline_path = os.path.join(parent_directory, BASELINE_FILE)
        if os.path.exists(baseline_path):
            with open(baseline_path, 'r') as f:
                return json.load(f)
    else:
        if os.path.exists(BASELINE_FILE):
            with open(BASELINE_FILE, 'r') as f:
                return json.load(f)
    return {}


def save_baselines(baselines):
    if os.path.basename(os.getcwd()) == "File_Integrity_Monitor":
        parent_directory = os.path.dirname(os.getcwd())
        baseline_path = os.path.join(parent_directory, BASELINE_FILE)
        
        with open(baseline_path, "w") as f:
            json.dump(baselines, f, indent=4)
    else:
        with open(BASELINE_FILE, "w") as f:
            json.dump(baselines, f, indent=4)

file_baselines = load_baselines()

def file_fingerprint(path):
    sha256 = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

def Create_Baselines(files):
    for file in files:
        try:
            file_baselines[file] = file_fingerprint(file)
        except FileNotFoundError:
            print(f"The file {file} does not exist!")
        except Exception as e:
            print(f"An error occurred with file {file}: {e}")
    save_baselines(file_baselines)    

if __name__ == "__main__":
    Create_Baselines(sys.argv[1:])
    print(file_baselines)