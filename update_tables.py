import urllib.request
import ipaddress
import os
import concurrent.futures
import json
import time
from datetime import datetime, timezone

def fetch_url_lines(url):
    """
    Fetches content from a URL and returns a list of cleaned lines.
    Runs in a separate thread.
    """
    print(f"Fetching {url}...")
    lines = []
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            data = response.read().decode('utf-8')
            for line in data.splitlines():
                line = line.strip()
                # Remove comments and empty lines
                if not line or line.startswith('#'):
                    continue
                # Remove inline comments
                if '#' in line:
                    line = line.split('#')[0].strip()
                if line:
                    lines.append(line)
    except Exception as e:
        print(f"Error fetching {url}: {e}")
    return lines

def get_ip_list(url_file, exclusion_file):
    myset = set()
    urls = []
    source_stats = {} # Track how many IPs came from each source
    
    # Read URLs from file
    try:
        with open(url_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"File not found: {url_file}")
        return myset, source_stats

    # 1. Optimization: Parallel Fetching
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # Submit all download tasks
        future_to_url = {executor.submit(fetch_url_lines, url): url for url in urls}
        
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            lines = future.result()
            count_for_source = 0
            
            for line in lines:
                try:
                    if '/' in line:
                        # It's a network (CIDR)
                        myset.add(ipaddress.ip_network(line, strict=False))
                        count_for_source += 1
                    else:
                        # It's a single IP
                        addr = ipaddress.ip_address(line)
                        if isinstance(addr, ipaddress.IPv4Address):
                            myset.add(ipaddress.IPv4Network(f"{line}/32"))
                        else:
                            myset.add(ipaddress.IPv6Network(f"{line}/128"))
                        count_for_source += 1
                except ValueError:
                    continue 
            source_stats[url] = count_for_source

    # Process Exclusions
    if os.path.exists(exclusion_file):
        with open(exclusion_file, 'r') as f:
            exclusions = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        exclusion_objs = set()
        for exc in exclusions:
            try:
                if '/' in exc:
                    exclusion_objs.add(ipaddress.ip_network(exc, strict=False))
                else:
                    # Handle single IP exclusions
                    addr = ipaddress.ip_address(exc)
                    if isinstance(addr, ipaddress.IPv4Address):
                         exclusion_objs.add(ipaddress.IPv4Network(f"{exc}/32"))
                    else:
                         exclusion_objs.add(ipaddress.IPv6Network(f"{exc}/128"))
            except ValueError:
                pass
        
        # Set difference is very fast
        myset = myset - exclusion_objs
    
    return myset, source_stats

def write_files(ip_set, output_dir, merged_filename):
    # Separate v4 and v6 for collapsing
    v4_list = []
    v6_list = []

    for ip in ip_set:
        if ip.version == 6:
            v6_list.append(ip)
        else:
            v4_list.append(ip)

    print(f"  Collapsing {len(ip_set)} networks (this may take a moment)...")
    
    collapsed_v4 = list(ipaddress.collapse_addresses(v4_list))
    collapsed_v6 = list(ipaddress.collapse_addresses(v6_list))

    ipv6_set = []
    network_set = []
    single_ip_set = []
    
    # Analytics
    total_ipv4_addresses = 0
    cidr_breakdown = {}

    # Process IPv6
    ipv6_set.extend(collapsed_v6)

    # Process IPv4
    for ip in collapsed_v4:
        total_ipv4_addresses += ip.num_addresses
        
        # Analytics: CIDR Breakdown
        prefix = str(ip.prefixlen)
        cidr_breakdown[prefix] = cidr_breakdown.get(prefix, 0) + 1

        if ip.prefixlen == 32:
             single_ip_set.append(ip)
        else:
            network_set.append(ip)

    # 3. Optimization: Sorting
    ipv6_set.sort(key=lambda x: (x.network_address, x.prefixlen))
    network_set.sort(key=lambda x: (x.network_address, x.prefixlen))
    single_ip_set.sort(key=lambda x: (x.network_address, x.prefixlen))
    
    # Merge sorted lists for the main file
    full_list = ipv6_set + network_set + single_ip_set
    full_list.sort(key=lambda x: (x.version, x.network_address, x.prefixlen))

    # Helper to stringify
    def stringify(obj):
        if obj.version == 4 and obj.prefixlen == 32:
            return str(obj.network_address)
        if obj.version == 6 and obj.prefixlen == 128:
            return str(obj.network_address)
        return str(obj)

    # Write sub-files
    os.makedirs(output_dir, exist_ok=True)

    with open(os.path.join(output_dir, 'ipv6.txt'), 'w') as f:
        f.writelines(stringify(ip) + '\n' for ip in ipv6_set)
            
    with open(os.path.join(output_dir, 'networks.txt'), 'w') as f:
        f.writelines(stringify(ip) + '\n' for ip in network_set)

    with open(os.path.join(output_dir, 'single_ips.txt'), 'w') as f:
        f.writelines(stringify(ip) + '\n' for ip in single_ip_set)

    # Write merged file
    with open(merged_filename, 'w') as f:
        f.writelines(stringify(ip) + '\n' for ip in full_list)
    
    print(f"Processed and optimized for {merged_filename}:")
    print(f"  - IPv6: {len(ipv6_set)}")
    print(f"  - Networks: {len(network_set)}")
    print(f"  - Single IPs: {len(single_ip_set)}")
    print(f"  - Total IPv4 Coverage: {total_ipv4_addresses} individual addresses")

    # Return stats for dashboard
    return {
        "ipv6_count": len(ipv6_set),
        "networks_count": len(network_set),
        "single_ips_count": len(single_ip_set),
        "total_optimized_count": len(full_list),
        "top_metrics": {
            "total_ipv4_addresses_covered": total_ipv4_addresses,
            "cidr_distribution": cidr_breakdown
        }
    }

def main():
    start_time = time.time()
    
    # Dashboard Data Structure
    dashboard_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "execution_duration_seconds": 0,
        "inbound": {},
        "outbound": {}
    }

    # Inbound
    print("Processing Inbound...")
    inbound_ips, inbound_sources = get_ip_list('tables/inbound/urltable_inbound', 'tables/inbound/urlexclusion_inbound')
    inbound_stats = write_files(inbound_ips, 'tables/inbound', 'inbound.txt')
    
    dashboard_data["inbound"] = {
        "sources": inbound_sources,
        "raw_total": sum(inbound_sources.values()),
        "unique_pre_collapse": len(inbound_ips),
        "stats": inbound_stats
    }

    # Outbound
    print("\nProcessing Outbound...")
    outbound_ips, outbound_sources = get_ip_list('tables/outbound/urltable_outbound', 'tables/outbound/urlexclusion_outbound')
    outbound_stats = write_files(outbound_ips, 'tables/outbound', 'outbound.txt')

    dashboard_data["outbound"] = {
        "sources": outbound_sources,
        "raw_total": sum(outbound_sources.values()),
        "unique_pre_collapse": len(outbound_ips),
        "stats": outbound_stats
    }

    # Finalize Time
    end_time = time.time()
    dashboard_data["execution_duration_seconds"] = round(end_time - start_time, 2)

    # --- Stats Folder Logic ---
    stats_dir = 'stats'
    os.makedirs(stats_dir, exist_ok=True)

    # 1. Historical File: stats_YYYYMMDD_HHMMSS.json
    timestamp_str = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    history_filename = f"stats_{timestamp_str}.json"
    history_path = os.path.join(stats_dir, history_filename)

    with open(history_path, 'w') as f:
        json.dump(dashboard_data, f, indent=4)
    
    # 2. Latest File: latest.json (always overwrites the previous latest)
    latest_path = os.path.join(stats_dir, 'latest.json')
    with open(latest_path, 'w') as f:
        json.dump(dashboard_data, f, indent=4)

    print(f"\nStatistics saved:")
    print(f"  - History: {history_path}")
    print(f"  - Latest:  {latest_path}")

if __name__ == "__main__":
    main()
