import hashlib
import File_Integrity_Monitor.Baseline as Baseline
import logging
import sys

def create_logger():
    file_change_logger = logging.getLogger("file_change")
    file_change_handler = logging.FileHandler("file_change.log", delay=False)
    file_change_handler.setLevel(logging.WARNING)
    file_change_formatter = logging.Formatter("%(asctime)s\n%(message)s")
    file_change_handler.setFormatter(file_change_formatter)
    file_change_logger.addHandler(file_change_handler)
    file_change_logger.propagate = False
    return file_change_logger
'''
Reads through the binary of a file in chunks. Every chunk creates
an update in the hash. This continues until there's nothing to read.
'''
def file_fingerprint(path):
    sha256 = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

#Logs when a difference in fingerprints is detected, and checks for other errors too
def monitor_files(files):
    print(files)
    logger = create_logger()
    for file in files:
        try:
            file_baseline = Baseline.file_baselines.get(file)
            if file_baseline:
                if file_fingerprint(file) != file_baseline:
                    logger.warning(f"The file: {file} was changed\n")
            else:
                Baseline.Create_Baselines([file])
                print(f"The file {file} doesn't have a baseline yet, creating baseline...")
        except FileNotFoundError:
            print(f"The file {file} does not exist!")
        except Exception as e:
            print(f"An error occurred with file {file}: {e}")

def job(arguments):
    monitor_files(arguments)

