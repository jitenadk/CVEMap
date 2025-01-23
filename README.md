# CVEMap

CVEMap is an automated vulnerability scanning utility that performs host discovery, scans open ports, identifies services, and maps known CVEs (Common Vulnerabilities and Exposures) for the detected services. It leverages Nmap for network scanning and integrates with SearchSploit for exploit information.

## **Table of Contents**
1. [Features](#features)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Dependencies](#dependencies)
5. [License](#license)
6. [Acknowledgements](#acknowledgements)

---

## **Features**
- **Host Discovery**: Scans a network range to identify live hosts.
- **Interface Scanning**: Scans all network interfaces automatically.
- **Open Port Detection**: Lists open TCP ports.
- **Service Detection**: Detects services running on open ports and their versions.
- **Vulnerability Mapping**: Fetches known CVEs for identified services using SearchSploit.
- **User-friendly Output**: Provides a detailed, color-coded console output.

---

## **Installation**

1. **Clone the repository**:
    ```bash
    git clone https://github.com/jitenadk/CVEMap.git
    cd CVEMap
    ```

2. **Install dependencies**:
    Install Python packages:
    ```bash
    pip install -r requirements.txt
    ```
    Ensure the following tools are installed:
    - `Nmap`: `sudo apt install nmap`
    - `SearchSploit`: `sudo apt install exploitdb`

---

## **Usage**
Run the script as follows:
```bash
python3 CVEMap.py
