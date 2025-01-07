# YARF (Yet Another Recon Framework) 🥷⚔️

**YARF** is a Bash script that automates recon for web app pentests. It integrates various tools to streamline tasks like root domain and subdomain enumeration, bruteforcing, endpoint discovery, service scanning, tech stack fingerprinting, and vulnerability scanning, organizing the output in a clean directory structure.



## ⚡ Features

- **Automated Directory Setup** 📂: Creates a structured directory for storing recon data.
- **Root Domain Enumeration** 🌐: Leverages Whois and ASN data via `Amass`.
- **Subdomain Enumeration** 🔍: Uses tools like `Amass` and `Subfinder`.
- **Spidering** 🕸️: Crawls targets with `Gospider`, `Hakrawler`, and `Katana`.
- **Dirbusting** 💥: Uses `Feroxbuster` with customizable wordlists.
- **Shodan Querying** 🛰️: Queries Shodan without an API key using `smap-scanner`.
- **Service Scanning** 🔌: Performs comprehensive scans with `nmap`.
- **Tech Stack Fingerprinting** 🫆: Utilizes `WAFW00F`, `Webanalyze`, and `WhatWeb`.
- **Vulnerability Scanning** 🚨: Scans for vulnerabilities with `Nikto` and `Nuclei`.



## ⚙️ Requirements

Ensure the following tools are installed and available in your `$PATH`:

- `dig` 🪏
- `amass` 🌍
- `subfinder` 🔍
- `gospider` 🕷️
- `hakrawler` 🧭
- `katana` 🗡️
- `feroxbuster` 💥
- `smap-scanner` 🛰️
- `nmap` 🎯
- `nikto` 🚨
- `nuclei` ⚛️
- `wafw00f` 🐶
- `webanalyze` 🕵️
- `whatweb` 🔎

### 📝 Wordlist

By default, YARF uses the following wordlist for `Feroxbuster`:
`/usr/share/seclists/Discovery/Web-Content/common.txt`. You can specify a custom wordlist using the `-wordlist` flag. 🗂️


## 🚀 Usage

Run the script with the following arguments:

```bash
./yarf.sh -org <organization_name> -d <domain> [-ip <ip_range>] [-wordlist <path>]
```


## 🗣️ Arguments

- `-org`: **(Required)** Organization name to find related root domains. 🏢
- `-d`: **(Required)** Target domain for reconnaissance. 🌐
- `-ip`: **(Optional)** IP range for scanning. 🔌
- `-wordlist`: **(Optional)** Custom wordlist for `Feroxbuster`. 📜


## 💡 Example

```bash
./yarf.sh -org ExampleCorp -d example.com -ip 192.168.1.0/24 -wordlist /path/to/custom-wordlist.txt
```


## 📂 Output

All results are stored under a directory named `YARF/<organization_name>_pentest` in the user’s home directory. The structure includes:

- **`00_domain_and_subdomain_enumeration`** 🌍: Results of domain and subdomain enumeration.
- **`01_spidering_and_brute_forcing_endpoints`** 🕸️: Crawling and brute-forcing results.
- **`02_server_side_scans`** 🔌: Results of server-side scans.
- **`03_tech_stack_fingerprinting_and_vuln_scans`** 🫆: Tech stack fingerprinting and vulnerability scanning results.
- **`04_vuln_validation_and_exploitation`** ⚔️: Reserved for manual validation and exploitation.


## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome! Feel free to open an issue or submit a pull request. 🙌


## 📜 License

This project is licensed under the GPL3 License. See the `LICENSE` file for details. ⚖️


## ⚠️ Disclaimer

**YARF is intended for authorized penetration testing and security assessments.** Use responsibly and ensure compliance with local laws and regulations. Unauthorized use is illegal and unethical. 🛑
