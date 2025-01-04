#!/bin/bash

#set -x #uncomment to debug

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -org)
      ORG_NAME="$2"
      echo "ORG_NAME set to $ORG_NAME"
      shift 2
      ;;
    -d)
      DOMAIN="$2"
      echo "DOMAIN set to $DOMAIN"
      shift 2
      ;;
    -ip)
      IP_RANGE="$2"
      echo "IP_RANGE set to $IP_RANGE"
      shift 2
      ;;
    -wordlist)
      WORDLIST="$2"
      echo "WORDLIST set to $WORDLIST"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1"
      echo "Usage: $0 -org <organization_name> -d <domain> [-ip <ip_range>] [-wordlist <path>]"
      exit 1
      ;;
  esac
done

# Validate required arguments
if [ -z "$ORG_NAME" ] || [ -z "$DOMAIN" ]; then
    echo "Usage: $0 -org <organization_name> -d <domain> [-ip <ip_range>] [-wordlist <path>]"
    exit 1
fi


# Display ASCII Art
cat << "EOF"

      _____                    _____                    _____                    _____          
     |\    \                  /\    \                  /\    \                  /\    \         
     |:\____\                /::\    \                /::\    \                /::\    \        
     |::|   |               /::::\    \              /::::\    \              /::::\    \       
     |::|   |              /::::::\    \            /::::::\    \            /::::::\    \      
     |::|   |             /:::/\:::\    \          /:::/\:::\    \          /:::/\:::\    \     
     |::|   |            /:::/__\:::\    \        /:::/__\:::\    \        /:::/__\:::\    \    
     |::|   |           /::::\   \:::\    \      /::::\   \:::\    \      /::::\   \:::\    \   
     |::|___|______    /::::::\   \:::\    \    /::::::\   \:::\    \    /::::::\   \:::\    \  
     /::::::::\    \  /:::/\:::\   \:::\    \  /:::/\:::\   \:::\____\  /:::/\:::\   \:::\    \ 
    /::::::::::\____\/:::/  \:::\   \:::\____\/:::/  \:::\   \:::|    |/:::/  \:::\   \:::\____\
   /:::/~~~~/~~      \::/    \:::\  /:::/    /\::/   |::::\  /:::|____|\::/    \:::\   \::/    /
  /:::/    /          \/____/ \:::\/:::/    /  \/____|:::::\/:::/    /  \/____/ \:::\   \/____/ 
 /:::/    /                    \::::::/    /         |:::::::::/    /            \:::\    \     
/:::/    /                      \::::/    /          |::|\::::/    /              \:::\____\    
\::/    /                       /:::/    /           |::| \::/____/                \::/    /    
 \/____/                       /:::/    /            |::|  ~|                       \/____/     
                              /:::/    /             |::|   |                                   
                             /:::/    /              \::|   |                                   
                             \::/    /                \:|   |                                   
                              \/____/                  \|___|                                   
                                                                                                
EOF

# Variables
BASE_DIR="$HOME/YARF/${ORG_NAME}_pentest"
WORDLIST="${WORDLIST:-/usr/share/seclists/Discovery/Web-Content/common.txt}"
EXTENSIONS="php,html,js,txt,bak,backup,old"

echo "BASE_DIR set to $BASE_DIR"

# Create Directory Structure
echo "Creating directory structure..."
mkdir -p "$BASE_DIR"/{00_domain_and_subdomain_enumeration,01_spidering_and_brute_forcing_endpoints,02_server_side_scans,03_tech_stack_fingerprinting_and_vuln_scans,04_vuln_validation_and_exploitation}

# Sub-directories
AMASS_OUTPUT_DIR="$BASE_DIR/00_domain_and_subdomain_enumeration/00_amass"
NSLOOKUP_OUTPUT_DIR="$BASE_DIR/00_domain_and_subdomain_enumeration/01_nslookup"
ACTIVE_RECON_DIR="$BASE_DIR/00_domain_and_subdomain_enumeration/02_active_recon"
ASN_ANALYSIS_DIR="$BASE_DIR/00_domain_and_subdomain_enumeration/03_asn_analysis"
SUBFINDER_OUTPUT_DIR="$BASE_DIR/00_domain_and_subdomain_enumeration/04_subfinder"
BRUTE_OUTPUT_DIR="$BASE_DIR/00_domain_and_subdomain_enumeration/05_bruteforce"
COMBINED_RESULTS_DIR="$BASE_DIR/00_domain_and_subdomain_enumeration/06_combined_results"
SPIDER_AND_DIRBUST_DIR="$BASE_DIR/01_spidering_and_brute_forcing_endpoints"
SERVER_SIDE_DIR="$BASE_DIR/02_server_side_scans"
SMAP_OUTPUT_DIR="$SERVER_SIDE_DIR/smap_scanner"
NMAP_OUTPUT_DIR="$SERVER_SIDE_DIR/nmap_scanner"
TECH_STACK_DIR="$BASE_DIR/03_tech_stack_fingerprinting_and_vuln_scans"

mkdir -p "$AMASS_OUTPUT_DIR" "$NSLOOKUP_OUTPUT_DIR" "$ACTIVE_RECON_DIR" "$ASN_ANALYSIS_DIR" "$SUBFINDER_OUTPUT_DIR" "$BRUTE_OUTPUT_DIR" "$COMBINED_RESULTS_DIR" "$SMAP_OUTPUT_DIR" "$NMAP_OUTPUT_DIR" "$TECH_STACK_DIR"
echo "Directory structure created."

# Environment Variables for Pentest
export ORG_NAME="$ORG_NAME"
export BASE_DIR="$BASE_DIR"
export DOMAIN="$DOMAIN"
export IP_RANGE="$IP_RANGE"
echo "Environment variables set."

# Reverse DNS Lookup
echo "Running reverse DNS lookup using nslookup..."
nslookup "$DOMAIN" | tee "$NSLOOKUP_OUTPUT_DIR/nslookup_output.txt" || {
  echo "Error: nslookup failed. Please verify the domain name."; exit 1;
}
echo "Reverse DNS lookup completed."

# Active Reconnaissance: Amass
if [ -n "$IP_RANGE" ]; then
  echo "Running Amass intel for IP_RANGE $IP_RANGE..."
  amass intel -active -addr "$IP_RANGE" | tee "$ACTIVE_RECON_DIR/amass_active_recon.txt"
fi
echo "Running Amass intel for DOMAIN $DOMAIN..."
amass intel -whois -d "$DOMAIN" | tee "$ACTIVE_RECON_DIR/amass_whois.txt"
amass intel -org "$ORG_NAME" | tee "$ASN_ANALYSIS_DIR/amass_org_asns.txt"
echo "Amass reconnaissance completed."

ASN=$(grep -oE '\b[0-9]+\b' "$ASN_ANALYSIS_DIR/amass_org_asns.txt" | head -1)
if [ ! -z "$ASN" ]; then
  echo "Running Amass intel for ASN $ASN..."
  amass intel -asn "$ASN" | tee "$ASN_ANALYSIS_DIR/amass_asn_domains.txt"
  echo "ASN analysis completed."
fi

# Subdomain Enumeration
echo "Running Amass subdomain enumeration..."
amass enum -d "$DOMAIN" -dir "$AMASS_OUTPUT_DIR"
sed 's/\x1b\[[0-9;]*m//g' "$AMASS_OUTPUT_DIR/amass.txt" | grep --color=never -oE '\b[a-zA-Z0-9.-]+\.$DOMAIN\b' | sort -u > "$AMASS_OUTPUT_DIR/amass_cleaned.txt"
echo "Running Subfinder..."
subfinder -d "$DOMAIN" | sort -u | tee "$SUBFINDER_OUTPUT_DIR/subfinder.txt"
echo "Subdomain enumeration completed."

# Brute-forcing
echo "Running Amass brute-forcing..."
amass enum -brute -d "$DOMAIN" -dir "$BRUTE_OUTPUT_DIR"
sed 's/\x1b\[[0-9;]*m//g' "$BRUTE_OUTPUT_DIR/amass.txt" | grep --color=never -oE '\b[a-zA-Z0-9.-]+\.$DOMAIN\b' | sort -u > "$BRUTE_OUTPUT_DIR/amass_brute_cleaned.txt"
echo "Comparing brute-forced results..."
comm -23 "$BRUTE_OUTPUT_DIR/amass_brute_cleaned.txt" "$AMASS_OUTPUT_DIR/amass_cleaned.txt" > "$BRUTE_OUTPUT_DIR/amass_brute_compared.txt"
echo "Brute-forcing completed."

# Combine Results
echo "Combining results..."
cat "$AMASS_OUTPUT_DIR/amass_cleaned.txt" "$BRUTE_OUTPUT_DIR/amass_brute_cleaned.txt" | sort -u > "$COMBINED_RESULTS_DIR/combined_amass_enum_and_bruteforced.txt"
cat "$COMBINED_RESULTS_DIR/combined_amass_enum_and_bruteforced.txt" "$SUBFINDER_OUTPUT_DIR/subfinder.txt" | sort -u > "$COMBINED_RESULTS_DIR/combined_amass_and_subfinder.txt"
sed 's/^/http:\/\//' "$COMBINED_RESULTS_DIR/combined_amass_and_subfinder.txt" > "$COMBINED_RESULTS_DIR/combined_amass_and_subfinder_with_http_prefix.txt"
echo "Results combined."

# Crawling with Tools
echo "Running Gospider..."
mkdir -p "$SPIDER_AND_DIRBUST_DIR/00_gospider"
gospider -S "$COMBINED_RESULTS_DIR/combined_amass_and_subfinder_with_http_prefix.txt" -q -d 5 -t 10 -c 10 -m 15 --include-subs --other-source --robots --sitemap -o "$SPIDER_AND_DIRBUST_DIR/00_gospider"
if ls "$SPIDER_AND_DIRBUST_DIR/00_gospider"/* 1> /dev/null 2>&1; then
  echo "Concatenating Gospider results..."
  cat "$SPIDER_AND_DIRBUST_DIR/00_gospider"/* > "$SPIDER_AND_DIRBUST_DIR/01_gospider.txt"
else
  echo "No files found in $SPIDER_AND_DIRBUST_DIR/00_gospider to concatenate."
  touch "$SPIDER_AND_DIRBUST_DIR/01_gospider.txt"
fi

echo "Running Hakrawler..."
hakrawler -d 5 -t 10 -timeout 3600 -insecure -subs -s -w -u < "$COMBINED_RESULTS_DIR/combined_amass_and_subfinder_with_http_prefix.txt" | tee "$SPIDER_AND_DIRBUST_DIR/02_hakrawler.txt"
echo "Running Katana..."
katana -list "$COMBINED_RESULTS_DIR/combined_amass_and_subfinder_with_http_prefix.txt" -headless -d 5 -jc -aff -fx -o "$SPIDER_AND_DIRBUST_DIR/03_katana.txt"
echo "Crawling completed."

# Combine Crawling Outputs
echo "Combining crawling results..."
cat "$SPIDER_AND_DIRBUST_DIR/01_gospider.txt" \
    "$SPIDER_AND_DIRBUST_DIR/02_hakrawler.txt" \
    "$SPIDER_AND_DIRBUST_DIR/03_katana.txt" | \
grep -Eo 'https?://[a-zA-Z0-9./?=_-]*$DOMAIN[^\"]*' | sort -u > "$SPIDER_AND_DIRBUST_DIR/04_combined_endpoints.txt"
echo "Crawling results combined."

# Feroxbuster with Custom Wordlist
echo "Running Feroxbuster..."
mkdir -p "$SPIDER_AND_DIRBUST_DIR/05_feroxbuster"
while read -r URL; do
  echo "Running Feroxbuster for $URL..."
  feroxbuster -t 50 \
    -w "$WORDLIST" \
    -x "$EXTENSIONS" \
    -e \
    --depth 5 \
    -H "User-Agent: Mozilla/5.0" \
    -o "$SPIDER_AND_DIRBUST_DIR/05_feroxbuster/$(echo $URL | sed 's|https\?://||' | tr -d '/').txt" \
    -u "$URL" -r -k -C 404 -E -B -g
  echo "Feroxbuster scan completed for $URL."
done < "$COMBINED_RESULTS_DIR/combined_amass_and_subfinder_with_http_prefix.txt"
echo "Feroxbuster scanning completed."

# Server-side Scanning: smap-scanner
run_smap_scan() {
    local domain="$1"
    local output_dir="$2"

    echo "Running smap-scanner for $domain..."
    if ! smap-scanner "$domain" -oA "$output_dir/smap"; then
        echo "Error: smap-scanner failed for $domain. Please verify the domain and try again."
        echo "Attempting fallback with nmap..."
        nmap -v -Pn -T3 -p- --open --min-rate=1000 -A -oA "$output_dir/nmap_fallback" "$domain"
        return 1
    fi
    echo "smap-scanner completed. Results saved in $output_dir"
}

# Server-side Scanning: nmap
run_nmap_scan() {
    local domain="$1"
    local output_dir="$2"

    echo "Running nmap scan for $domain..."
    if ! nmap -v -Pn -T3 -p- --open --min-rate=1000 -A -oA "$output_dir/nmap" "$domain"; then
        echo "Error: nmap scan failed for $domain. Please verify the domain and try again."
        return 1
    fi
    echo "nmap scan completed. Results saved in $output_dir"
}

# Execute smap-scanner
run_smap_scan "$DOMAIN" "$SMAP_OUTPUT_DIR" || {
    echo "smap-scanner failed. Skipping further actions for smap-scanner."
}

# Execute nmap scan
run_nmap_scan "$DOMAIN" "$NMAP_OUTPUT_DIR" || {
    echo "nmap scan failed. Skipping further actions for nmap."
}

echo "Running tech stack fingerprinting and vulnerability scanning..."

# Tech Stack Fingerprinting and Vulnerability Scanning
run_nikto_scan() {
    local domain="$1"
    local output_file="$2"

    echo "Running Nikto scan for $domain..."
    if ! nikto -h "$domain" -p 80,443 -useragent "Mozilla/5.0" -Tuning x | tee "$output_file"; then
        echo "Error: Nikto scan failed for $domain."
        return 1
    fi
    echo "Nikto scan completed. Results saved in $output_file"
}

run_nuclei_scan() {
    local domain="$1"
    local output_file="$2"

    echo "Running Nuclei scan for $domain..."
    if ! nuclei -as -u "$domain" -o "$output_file" --silent; then
        echo "Error: Nuclei scan failed for $domain." | tee -a "$output_file"
        return 1
    fi
    echo "Nuclei scan completed. Results saved in $output_file"
}

run_wafw00f_scan() {
    local domain="$1"
    local output_file="$2"

    echo "Running WAFW00F scan for $domain..."
    if ! wafw00f "$domain" -a -v -r | tee "$output_file"; then
        echo "Error: WAFW00F scan failed for $domain."
        return 1
    fi
    echo "WAFW00F scan completed. Results saved in $output_file"
}

run_webanalyze_scan() {
    local domain="$1"
    local output_file="$2"

    echo "Running Webanalyze scan for $domain..."
    if ! webanalyze -apps /usr/share/webanalyze/technologies.json -host "$domain" -crawl 50 -worker 10 -silent | tee "$output_file"; then
        echo "Error: Webanalyze scan failed for $domain."
        return 1
    fi
    echo "Webanalyze scan completed. Results saved in $output_file"
}

run_whatweb_scan() {
    local domain="$1"
    local output_file="$2"

    echo "Running WhatWeb scan for $domain..."
    if ! whatweb -v --no-errors -a 3 "$domain" | tee "$output_file"; then
        echo "Error: WhatWeb scan failed for $domain."
        return 1
    fi
    echo "WhatWeb scan completed. Results saved in $output_file"
}

# Execute Scans
run_nikto_scan "$DOMAIN" "$TECH_STACK_DIR/nikto.txt"
run_nuclei_scan "$DOMAIN" "$TECH_STACK_DIR/nuclei.txt"
run_wafw00f_scan "$DOMAIN" "$TECH_STACK_DIR/wafw00f.txt"
run_webanalyze_scan "$DOMAIN" "$TECH_STACK_DIR/webanalyze.txt"
run_whatweb_scan "$DOMAIN" "$TECH_STACK_DIR/whatweb.txt"
echo "Tech stack fingerprinting and vulnerability scanning completed."

echo "Pentesting directory and scans are completed. Results stored in $BASE_DIR."
