# DNS-Cache_Monitor
Note: DNS_Access.py will be more of a work in progress due to the dependence of the operating
system and its version. For now, it may or may not work on a windows machine.

## Requirements
Include the baselines.py requirement

This script uses `signtool` to verify if an executable is signed by Microsoft or other trusted authorities. `signtool` is part of the Windows SDK.

### Installing the Windows SDK
1. Download the Windows SDK from the [official website](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/).
2. During installation, select the **Signing Tools for Desktop Apps** feature.
3. After installation, ensure the SDK's `bin` directory is added to your system's PATH, or provide the full path to `signtool.exe` in the script.

Flask stuff for future development into scheduling and hosting on a web server to allow
real time hosting of a machine's threats.

Include .env for api key and virustotal api stuff

Include future exansion to allow for full automation

Include experimental/Scrapped dns cache monitor

For persistent storage scanner, note that directory scanning gives you insight into potential or inactive threats that might not have been loaded yet or that could be loaded later, which is different from launchctl list