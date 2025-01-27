from File_Integrity_Monitor import File_Monitor
from Process_Monitor import Process_Monitor
from Network_Monitor import Network_Monitor
import argparse
from flask import Flask, render_template, request
import os
import threading
import time



def parse_arguments():
    parser = argparse.ArgumentParser(
        description="A threat dashboard script to monitor processes and files."
    )

    # Smart process detection flag: -s
    parser.add_argument(
        "-s",
        "--smart",
        action="store_true",
        help="Enable smart process detection",
    )

    # Positional arguments for files to monitor
    parser.add_argument(
        "files",
        nargs="*",
        help="List of files to monitor. Provide file paths separated by spaces.",
    )

    parser.add_argument(
        "--dns_log_path",
        required=True, 
        help="Path to the dnsmasq/other dns log file.",
    )

    # Parse the arguments
    args = parser.parse_args()
    return args

args = parse_arguments()

name = os.name
operating_system = ""
if name == "nt":
    operating_system = "w"
elif name == "posix":
    operating_system = "m"

File_Monitor.job(args.files)
Process_Monitor.job(operating_system, args.smart)

dns_data = []
file_data = []
process_data = []

last_position = 0
dns_data_lock = threading.Lock()
def read_log(log_name):
    global last_position
    try:
        with open(log_name, 'r') as f:
            if log_name == "malicious_ips.log":
                f.seek(last_position)
                while True:
                    first_line = f.readline().strip()
                    second_line = f.readline().strip()

                    if not first_line or not second_line:
                        break

                    remaining_lines = []
                    while True:
                        line = f.readline().strip()
                        if not line: 
                            break
                        remaining_lines.append(line)

                    with dns_data_lock:
                        dns_data.append([first_line, second_line, remaining_lines])

                last_position = f.tell()
            elif log_name == "file_change.log":
                while True:
                    datetime = f.readline().strip()
                    if not datetime:
                        break
                    line = f.readline().strip()
                    f.readline().strip()
                    file_data.append([datetime, line])
            elif log_name == "suspicious_processes.log":
                while True:
                    datetime = f.readline().strip()
                    if not datetime:
                        break
                    process = f.readline().strip()
                    hash = f.readline().strip()
                    yara = f.readline().strip()
                    ai = f.readline().strip()
                    f.readline().strip()
                    process_data.append([datetime, process, hash, yara, ai])
            else:
                print("Invalid log name")
    except FileNotFoundError:
        pass

read_log("file_change.log")
read_log("suspicious_processes.log")

def start_log_monitor():
    while True:
        read_log("malicious_ips.log")
        time.sleep(5)

def start_network_monitor():
    Network_Monitor.job(operating_system, args.dns_log_path)


if __name__ == "__main__":
    network_thread = threading.Thread(target=start_network_monitor)
    network_thread.daemon = True
    network_thread.start()

    log_thread = threading.Thread(target=start_log_monitor)
    log_thread.daemon = True  
    log_thread.start()

    app = Flask(__name__)

    @app.route("/", methods=['GET'])
    def home():
        return render_template("index.html", DnsData=dns_data, FileData=file_data, ProcessData=process_data)

    app.run(threaded=True)
