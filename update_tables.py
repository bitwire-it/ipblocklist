#!/usr/bin/env python3
import ipaddress
import logging
import pathlib
import shutil
import time
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor
import radix
import os
import re

# --- Configuration ---
INBOUND_BLOCKLIST_URL_FILE = "tables/inbound/urltable_inbound"
OUTBOUND_BLOCKLIST_URL_FILE = "tables/outbound/urltable_outbound"
INBOUND_EXCLUSION_URL_FILE = "tables/inbound/urlexclusion_inbound"
OUTBOUND_EXCLUSION_URL_FILE = "tables/outbound/urlexclusion_outbound"
INBOUND_IP_LIST_FILE = "inbound.txt"
OUTBOUND_IP_LIST_FILE = "outbound.txt"
IP_LIST_FILE = "ip-list.txt"
README_FILE = "README.md"
INBOUND_BLOCKLIST_DOWNLOAD_DIR = pathlib.Path("inbound_blocklist_temp")
OUTBOUND_BLOCKLIST_DOWNLOAD_DIR = pathlib.Path("outbound_blocklist_temp")
INBOUND_EXCLUSION_DOWNLOAD_DIR = pathlib.Path("inbound_exclusion_temp")
OUTBOUND_EXCLUSION_DOWNLOAD_DIR = pathlib.Path("outbound_exclusion_temp")

# --- Performance Configuration ---
MAX_CONCURRENT_DOWNLOADS = 25
REQUEST_TIMEOUT = 45
MAX_FILE_PROCESS_WORKERS = None

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(funcName)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# --- Shared HTTP Headers ---
HTTP_HEADERS = {
    "sec-ch-ua-platform": '"macOS"',
    "Accept": "*/*",
    "accept-encoding": "gzip, deflate, br, zstd",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "sec-ch-ua": '"Chromium";v="130", "Brave";v="130", "Not?A_Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "cache-control": "no-cache",
    "pragma": "no-cache",
    "sec-fetch-site": "same-origin",
    "sec-gpc": "1",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
}

# --- Regex for finding IP/CIDR ---
# Updated to support IPv4 and IPv6 (including CIDR /128)
IP_CIDR_REGEX = re.compile(
    r"\b("
    r"(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3})"   # Match IPv4
    r"|"
    r"(?:[0-9a-fA-F:]+:[0-9a-fA-F:]+)"     # Match IPv6 (Loose match for extraction)
    r")"
    r"(?:/\d{1,3})?"                       # Match optional CIDR (e.g., /24, /32, /128)
    r"\b"
)

def remove_old_files():
    files_to_remove = ["inbound.txt", "outbound.txt", "ip-list.txt"]
    for filename in files_to_remove:
        if os.path.exists(filename):
            os.remove(filename)
            print(f"Removed {filename}")
        else:
            print(f"{filename} does not exist, skipping.")

remove_old_files()

async def download_file(session: aiohttp.ClientSession, url: str, destination: pathlib.Path, semaphore: asyncio.Semaphore):
    """Asynchronously downloads a single file, respecting the semaphore."""
    async with semaphore:
        try:
            timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
            async with session.get(url, headers=HTTP_HEADERS, allow_redirects=True, ssl=False, timeout=timeout) as response:
                response.raise_for_status()
                with open(destination, "wb") as f_out:
                    f_out.write(f"# Source: {url}\n".encode("utf-8"))
                    f_out.write(await response.read())
                return url, True
        except Exception as e:
            logging.error(f"FAIL: {url} | Reason: {e}")
            return url, False

async def download_all_files(url_file: str, download_dir: pathlib.Path):
    """Reads URLs from a file and downloads them all concurrently, reporting progress."""
    url_list_path = pathlib.Path(url_file)
    if not url_list_path.exists():
        logging.warning(f"URL file not found: {url_file}. Skipping.")
        return

    if download_dir.exists():
        shutil.rmtree(download_dir)
    download_dir.mkdir(parents=True, exist_ok=True)

    with open(url_list_path) as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    if not urls:
        logging.info(f"No URLs to download from {url_file}.")
        return

    logging.info(f"Starting download of {len(urls)} files from {url_file}...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_DOWNLOADS)
    success_count, fail_count = 0, 0
    
    async with aiohttp.ClientSession() as session:
        tasks = [download_file(session, url, download_dir / f"{i}.txt", semaphore) for i, url in enumerate(urls)]
        for i, task in enumerate(asyncio.as_completed(tasks), 1):
            try:
                url, success = await task
                if success: success_count += 1
                else: fail_count += 1
                if i % 10 == 0 or i == len(urls):
                        logging.info(f"Downloads from {url_file}: [{i}/{len(urls)}] complete. (Success: {success_count}, Failed: {fail_count})")
            except Exception as e:
                fail_count += 1
                logging.error(f"A download task itself failed unexpectedly: {e}")
    
    logging.info(f"Finished all downloads for {url_file}. Success: {success_count}, Failed: {fail_count}")

def _process_file(file_path: pathlib.Path) -> set[str]:
    """
    Robust helper function to parse a single file.
    It uses a regular expression to find the first valid IP/CIDR on a line,
    ignoring any other text.
    """
    entries = set()
    source_url = str(file_path)
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("# Source:"):
                    source_url = line.split(":", 1)[1].strip()
                    continue
                
                # Clean the line of comments and whitespace
                clean_line = line.split("#")[0].split(";")[0].strip()
                if not clean_line:
                    continue

                # Search for an IP/CIDR pattern anywhere in the line
                match = IP_CIDR_REGEX.search(clean_line)
                
                if match:
                    ip_str = match.group(0) # Changed from group(1) to group(0) to capture full match including CIDR if inside group 1 wasn't capturing properly in new regex structure
                    # Correction: In the regex definition:
                    # Group 0 is the whole match (IP + CIDR)
                    # Group 1 is the IP part only
                    # We want the whole string to pass to ip_network, so group(0) is safer, 
                    # but let's check the regex structure.
                    # r"\b( ("IPv4"|"IPv6") (?:/\d{1,3})? )\b" -> The outer parenthesis creates Group 1.
                    # So match.group(1) is actually correct for the full string.
                    # However, to be absolutely safe with nested groups, group(0) (the whole match) is preferred 
                    # as long as the regex boundaries \b are correct.
                    
                    ip_to_validate = match.group(1)

                    try:
                        # Final validation
                        ipaddress.ip_network(ip_to_validate, strict=False)
                        entries.add(ip_to_validate)
                    except ValueError:
                        # Regex matched something that looked like an IP but wasn't (e.g. 999.999.999.999 or 12:34)
                        # logging.warning(f"Regex matched invalid IP '{ip_to_validate}' in {source_url}")
                        pass
                        
    except Exception as e:
        logging.error(f"Could not process file {file_path}: {e}")
    
    # Log the source URL if we found one, otherwise the file path
    logging.info(f"Parsed {len(entries)} entries from {source_url}")
    return entries

def parse_files_in_parallel(download_dir: pathlib.Path) -> set[str]:
    """Reads all files in a directory in parallel and returns a set of unique, clean lines."""
    if not download_dir.exists(): return set()
    file_paths = list(download_dir.glob("*.txt"))
    if not file_paths:
        if download_dir.exists():
            shutil.rmtree(download_dir)
        return set()

    logging.info(f"Parsing {len(file_paths)} files from {download_dir} in parallel...")
    all_entries = set()
    with ThreadPoolExecutor(max_workers=MAX_FILE_PROCESS_WORKERS) as executor:
        for result_set in executor.map(_process_file, file_paths):
            all_entries.update(result_set)
    shutil.rmtree(download_dir)
    return all_entries

def consolidate_networks_radix(ip_set: set[str], exclusion_set: set[str] = None) -> list[str]:
    """
    Consolidates networks using a Radix tree, applying exclusions and aggregating the result.
    This is the all-in-one, correct, and fast processing function.
    """
    if not ip_set: return []
    logging.info(f"Consolidating {len(ip_set):,} raw entries with Radix tree...")
    rtree = radix.Radix()
    invalid_count = 0

    # Step 1: Add all valid blocklist networks to the Radix tree.
    for ip_str in ip_set:
        try:
            rtree.add(str(ipaddress.ip_network(ip_str, strict=False)))
        except ValueError:
            invalid_count += 1
    if invalid_count > 0:
        logging.warning(f"Skipped {invalid_count:,} invalid IP/CIDR entries during population.")

    # Step 2: Remove all exclusion networks.
    if exclusion_set:
        logging.info(f"Applying {len(exclusion_set):,} exclusion entries...")
        invalid_excl_count = 0
        for ip_str in exclusion_set:
            try:
                excl_net_str = str(ipaddress.ip_network(ip_str, strict=False))
                # 1. Delete the exact exclusion network (if it exists)
                try:
                    rtree.delete(excl_net_str)
                except KeyError:
                    pass 

                # 2. Find and delete all subnets *covered by* this exclusion
                nodes_to_delete = rtree.search_covered(excl_net_str)
                if nodes_to_delete:
                    prefixes_to_delete = [node.prefix for node in nodes_to_delete]
                    for prefix in prefixes_to_delete:
                        try:
                            rtree.delete(prefix)
                        except KeyError:
                            pass

                            
            except ValueError:
                invalid_excl_count += 1
        
        if invalid_excl_count > 0:
            logging.warning(f"Skipped {invalid_excl_count:,} invalid exclusion entries.")

    # Step 3: Get all remaining prefixes.
    all_prefixes = rtree.prefixes()
    if not all_prefixes:
        logging.info("Consolidation complete. Result is an empty list.")
        return []
        
    # Step 4: Aggregate the list by removing subnets that are covered by larger nets.
    prefixes_to_remove = set()
    for prefix_str in all_prefixes:
        covered_nodes = rtree.search_covered(prefix_str)
        if len(covered_nodes) > 1:
            for node in covered_nodes:
                if node.prefix != prefix_str:
                    prefixes_to_remove.add(node.prefix)

    # Step 5: Create the final list by removing the identified subnets.
    consolidated_list = [p for p in all_prefixes if p not in prefixes_to_remove]
    
    logging.info(
        f"Consolidation complete. "
        f"Final Aggregated: {len(consolidated_list):,}"
    )

    # Step 6: Sort the final list for clean output.
    ipv4_list, ipv6_list = [], []
    for ip_str in consolidated_list:
        try:
            ip = ipaddress.ip_network(ip_str, strict=False)
            if ip.version == 4:
                ipv4_list.append(ip)
            else:
                ipv6_list.append(ip)
        except ValueError:
            continue
            
    ipv4_list.sort()
    ipv6_list.sort()
    return [str(ip) for ip in ipv4_list] + [str(ip) for ip in ipv6_list]

def calculate_total_ips(ip_list: list[str]) -> int:
    total_ips = 0
    MIN_PREFIX_IPV4 = 8
    MIN_PREFIX_IPV6 = 64

    for cidr_string in ip_list:
        try:
            network = ipaddress.ip_network(cidr_string)
            if network.version == 4:
                if network.prefixlen < MIN_PREFIX_IPV4:
                    logging.warning(f"Ignoring overly broad IPv4 network in stats: {cidr_string}")
                    continue
            elif network.version == 6:
            #   if network.prefixlen < MIN_PREFIX_IPV6:
                    # logging.warning(f"Ignoring overly broad IPv6 network in stats:. {cidr_string}")
                    continue
            
            total_ips += network.num_addresses
        except ValueError:
            logging.warning(f"Skipping invalid network during IP count: {cidr_string}")
            continue
            
    return total_ips

def format_number(num: int) -> str:
    """Formats large numbers with suffixes (K, M, B, T)."""
    if num >= 1_000_000_000_000: return f"{num / 1_000_000_000_000:.1f}T"
    if num >= 1_000_000_000: return f"{num / 1_000_000_000:.1f}B"
    if num >= 1_000_000: return f"{num / 1_000_000:.1f}M"
    if num >= 1_000: return f"{num / 1_000:.1f}K"
    return str(num)

def format_ip_for_output(cidr_string: str) -> str:
    """
    Formats an IP/CIDR string for the output file.
    - Removes '/32' from IPv4 addresses.
    - Removes '/128' from IPv6 addresses.
    - Keeps all other CIDR notations as is.
    """
    if cidr_string.endswith('/32') and ':' not in cidr_string:
         # Only remove /32 if it's IPv4 (checked by lack of colon, faster than parsing)
        return cidr_string[:-3]
    if cidr_string.endswith('/128'):
        return cidr_string[:-4]
    return cidr_string

def update_readme(inbound_count: int, outbound_count: int, inbound_total_ips: int, outbound_total_ips: int):
    """Updates README.md with current statistics and project information."""
    from datetime import datetime, timezone
    
    now_utc = datetime.now(timezone.utc)
    inbound_fmt = format_number(inbound_total_ips)
    outbound_fmt = format_number(outbound_total_ips)
    total_fmt = format_number(inbound_total_ips + outbound_total_ips)
    
    # The entire README content is structured here
    readme_content = f"""# IP Blocklist

![GitHub Repo stars](https://img.shields.io/github/stars/bitwire-it/ipblocklist)

<a href="https://www.buymeacoffee.com/Matis7" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>

This project provides aggregated IP blocklists for inbound and outbound traffic, updated every 2 hours. It includes exclusions for major public DNS resolvers to prevent legitimate services from being blocked.

---

## Live Statistics

![Inbound IPs](https://img.shields.io/badge/Inbound_IPs-{inbound_fmt}-red?style=flat-square) \
![Outbound IPs](https://img.shields.io/badge/Outbound_IPs-{outbound_fmt}-orange?style=flat-square) \
![Total IPs](https://img.shields.io/badge/Total_IPs-{total_fmt}-blue?style=flat-square) \
![Last Updated](https://img.shields.io/badge/Last_Updated-{now_utc.strftime('%Y--%m--%d')}-green?style=flat-square)

- **Inbound Blocklist**: {inbound_count:,} networks/IPs covering {inbound_total_ips:,} individual IP addresses
- **Outbound Blocklist**: {outbound_count:,} networks/IPs covering {outbound_total_ips:,} individual IP addresses
- **Total Coverage**: {inbound_total_ips + outbound_total_ips:,} individual IP addresses


---

## How to Use These Lists

These are standard text files and can be used with most modern firewalls, ad-blockers, and security tools.

### 🛡️ `inbound.txt` (Inbound Blocklist)

* **What it is:** A list of IPs/networks with a bad reputation for *initiating* malicious connections. This includes sources of spam, scanning, brute-force attacks (SSH, RDP), and web exploits.
* **Use Case:** Protect your public-facing servers and services (web servers, mail servers, game servers, etc.).
* **How to use:** Apply this list to your firewall's **WAN IN** or **INPUT** chain to **DROP** or **REJECT** all incoming traffic *from* these sources.

### ☢️ `outbound.txt` (Outbound Blocklist)

* **What it is:** A list of known malicious destination IPs. This includes C2 (Command & Control) servers, botnet controllers, malware drop sites, and phishing hosts.
* **Use Case:** Prevent compromised devices on your *internal* network (like a laptop or IoT device) from *contacting* malicious servers.
* **How to use:** Apply this list to your firewall's **LAN OUT** or **OUTPUT** chain to **BLOCK** or **LOG** all outgoing traffic *to* these destinations.

---

## Acknowledgements

🪨 **[borestad](https://www.github.com/borestad)** • *foundational blocklists* 🚀 **Code contributions**
- [David](https://github.com/dvdctn)
- [Garrett Laman](https://github.com/garrettlaman)

❤️ **Our sponsors** • *making this project possible*
- [mraxu](https://www.github.com/mraxu)
- Hareen
- Alexandru Balmus
- blockstreamtechnologies.llc

## License

### Code
The source code (including `update_tables.py`) is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

### Data
The aggregated blocklists (`inbound.txt`, `outbound.txt`, etc.) are derivative works containing data from multiple sources. 

**Usage of these lists is subject to the licenses of the original data providers.** - Many sources (e.g., Spamhaus) **prohibit commercial use** of their data without a separate agreement.
- Therefore, the aggregated data in this repository is provided under the **Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)** license.

**Attribution:**
This project relies on data from:

- [borestad/blocklist-abuseipdb](https://github.com/borestad/blocklist-abuseipdb)
- [borestad/firehol-mirror](https://github.com/borestad/firehol-mirror)
- [stamparm/ipsum](https://github.com/stamparm/ipsum)
- [ShadowWhisperer/IPs](https://github.com/ShadowWhisperer/IPs)
- [romainmarcoux/malicious-ip](https://github.com/romainmarcoux/malicious-ip)
- [romainmarcoux/malicious-outgoing-ip](https://github.com/romainmarcoux/malicious-outgoing-ip)
- [elliotwutingfeng/ThreatFox-IOC-IPs](https://github.com/elliotwutingfeng/ThreatFox-IOC-IPs)
- [binarydefense.com](https://www.binarydefense.com/banlist.txt)
- [bruteforceblocker.com](https://danger.rulez.sk/projects/bruteforceblocker/blist.php)
- [darklist.de](https://www.darklist.de/raw.php)
- [dan.me.uk Tor List](https://www.dan.me.uk/torlist/)
- [Emerging Threats](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
- [Spamhaus DROP](https://www.spamhaus.org/drop/drop.txt)
- [CINSscore](https://cinsscore.com/list/ci-badguys.txt)
- [CriticalPathSecurity](https://github.com/CriticalPathSecurity/Public-Intelligence-Feeds)
- [C2 Tracker](https://github.com/montysecurity/C2-Tracker)

---

*This README is automatically updated by the update script on {now_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}.*
"""
    try:
        with open(README_FILE, "w", encoding="utf-8") as f:
            f.write(readme_content)
        logging.info(f"Updated {README_FILE} successfully.")
    except Exception as e:
        logging.error(f"Failed to update {README_FILE}: {e}")

async def process_list(list_type: str, blocklist_url_file: str, exclusion_url_file: str,
                       blocklist_download_dir: pathlib.Path, exclusion_download_dir: pathlib.Path,
                       output_file: str):
    """Fully processes one type of list (e.g., 'inbound') from download to final file."""
    logging.info(f"--- Starting {list_type.upper()} List Processing ---")

    await asyncio.gather(
        download_all_files(blocklist_url_file, blocklist_download_dir),
        download_all_files(exclusion_url_file, exclusion_download_dir)
    )
    
    blocklist_entries = parse_files_in_parallel(blocklist_download_dir)
    exclusion_entries = parse_files_in_parallel(exclusion_download_dir)
    logging.info(f"Found {len(blocklist_entries):,} raw blocklist entries and {len(exclusion_entries):,} raw exclusion entries.")

    # --- DEBUGGING: Show a sample of exclusion entries ---
    if exclusion_entries:
        logging.info("--- START S_EXCLUSION_ENTRIES (SAMPLE) ---")
        excl_list_sample = list(exclusion_entries)
        # Log all entries if 20 or fewer, otherwise a sample
        if len(excl_list_sample) > 20:
            logging.info(f"Showing 20 of {len(excl_list_sample)} exclusion entries:")
            for i, entry in enumerate(excl_list_sample[:20]):
                logging.info(f"EXCL {i+1}: {entry}")
        else:
            logging.info(f"Showing all {len(excl_list_sample)} exclusion entries:")
            for i, entry in enumerate(excl_list_sample):
                logging.info(f"EXCL {i+1}: {entry}")
        
        # Specifically check for the problem range
        if "140.82.112.0/20" in exclusion_entries:
            logging.info(">>> DEBUG: Problem range '140.82.112.0/20' was successfully parsed from exclusion list.")
        else:
            logging.warning(">>> DEBUG: Problem range '140.82.112.0/20' was NOT found in the parsed exclusion set.")

        logging.info("--- END S_EXCLUSION_ENTRIES (SAMPLE) ---")
    else:
        logging.warning("No exclusion entries were found! The exclusion list may be empty or failed to parse.")


    if not exclusion_entries:
        final_list = consolidate_networks_radix(blocklist_entries, exclusion_set=set())
    else:
        final_list = consolidate_networks_radix(blocklist_entries, exclusion_entries)

    total_ips = calculate_total_ips(final_list)
    logging.info(f"Final {list_type} list: {len(final_list):,} networks covering {total_ips:,} individual IPs.")

    # Apply the custom formatting before writing to the file
    logging.info(f"Formatting {len(final_list):,} networks for output file...")
    output_lines = [format_ip_for_output(ip) for ip in final_list]

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(output_lines) + "\n")
    logging.info(f"Wrote final formatted list to {output_file}.")

    if list_type == "inbound":
        with open(IP_LIST_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(output_lines) + "\n")
        logging.info(f"Wrote final formatted list to {IP_LIST_FILE}.")

    return len(final_list), total_ips

async def main():
    """Main asynchronous script execution."""
    start_time = time.monotonic()
    inbound_task = process_list(
        "inbound", INBOUND_BLOCKLIST_URL_FILE, INBOUND_EXCLUSION_URL_FILE,
        INBOUND_BLOCKLIST_DOWNLOAD_DIR, INBOUND_EXCLUSION_DOWNLOAD_DIR, INBOUND_IP_LIST_FILE
    )
    outbound_task = process_list(
        "outbound", OUTBOUND_BLOCKLIST_URL_FILE, OUTBOUND_EXCLUSION_URL_FILE,
        OUTBOUND_BLOCKLIST_DOWNLOAD_DIR, OUTBOUND_EXCLUSION_DOWNLOAD_DIR, OUTBOUND_IP_LIST_FILE
    )
    (in_count, in_total), (out_count, out_total) = await asyncio.gather(inbound_task, outbound_task)
    
    update_readme(in_count, out_count, in_total, out_total)
    total_time = time.monotonic() - start_time
    logging.info("=" * 20 + " SCRIPT COMPLETE " + "=" * 20)
    logging.info(f"Total execution time: {total_time:.2f} seconds.")

if __name__ == "__main__":
    asyncio.run(main())
