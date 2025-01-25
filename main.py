from File_Integrity_Monitor import File_Monitor
from Process_Monitor import Process_Monitor
import argparse
from flask import Flask, render_template


'''Test on windows'''
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="A threat dashboard script to monitor processes and files."
    )

    # OS flag: -o (w for Windows, m for Mac)
    parser.add_argument(
        "-o",
        "--os",
        choices=["w", "m"],
        required=True,
        help="Specify the operating system: 'w' for Windows or 'm' for macOS.",
    )

    # Smart process detection flag: -s
    parser.add_argument(
        "-s",
        "--smart",
        action="store_true",
        help="Enable smart process detection if SDK is installed",
    )

    # Positional arguments for files to monitor
    parser.add_argument(
        "files",
        nargs="*",
        help="List of files to monitor. Provide file paths separated by spaces.",
    )

    # Parse the arguments
    args = parser.parse_args()
    return args

args = parse_arguments()

#if args.os == "w":
    #DNS_Monitor.job()
#DNS_Monitor.job()
File_Monitor.job(args.files)
Process_Monitor.job(args.os, args.smart)

dns_data = []
file_data = []
process_data = []


def read_log(log_name):
    try:
        with open(log_name, 'r') as f:
            if log_name == "malicious_ips.log":
                while True:
                    first_line = f.readline().strip()
                    second_line = f.readline().strip()

                    if not first_line or not second_line:
                        break

                    remaining_lines = []
                    while True:
                        line = f.readline().strip()
                        if not line:  # Stop if a blank line or EOF is encountered
                            break
                        remaining_lines.append(line)

                    dns_data.append([first_line, second_line, remaining_lines])

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

read_log("malicious_ips.log")
read_log("file_change.log")
read_log("suspicious_processes.log")
app = Flask(__name__)
@app.route("/")
def home():
    return render_template("index.html", DnsData=dns_data, FileData=file_data, ProcessData=process_data)
if __name__ == "__main__":
    app.run()