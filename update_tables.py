import urllib.request
from urllib.parse import urlparse
import ipaddress
import os
import concurrent.futures
import json
import time
import itertools
import logging
import re
from datetime import datetime, timezone
from typing import List, Dict, Set, Optional, Union, Tuple

# --- Configuration & Constants ---
MAX_RETRIES = 3
URL_TIMEOUT = 20
MIN_NETWORKS_FOR_MP = 1000
MAX_FETCH_WORKERS = 10
CHUNKS_PER_WORKER = 14
MAX_TASKS_PER_CHILD = 100

# Regex for finding IPv4 candidates in messy text (e.g. pipe delimited files)
# Matches 4 groups of 1-3 digits separated by dots, optionally followed by /CIDR
IPV4_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b')

# Global variables for worker processes to avoid pickling large datasets repeatedly
WORKER_GLOBAL_EXCL: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
WORKER_BUCKETS: Dict[int, List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]] = {}

# --- Logging Setup ---
# We'll configure logging in main() to avoid side effects on import
logger = logging.getLogger(__name__)

def init_worker(global_excl: List, buckets: Dict):
    """
    Initializer for worker processes to set global variables.
    This prevents re-pickling the exclusion lists for every task.
    """
    global WORKER_GLOBAL_EXCL, WORKER_BUCKETS
    WORKER_GLOBAL_EXCL = global_excl
    WORKER_BUCKETS = buckets

def is_safe_url(url: str) -> bool:
    """Validates that the URL scheme is http or https."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ('http', 'https') and bool(parsed.netloc)
    except Exception:
        return False

def fetch_url_lines(url: str) -> List[str]:
    """
    Fetches content from a URL and returns a list of cleaned lines.
    Runs in a separate thread. Retries on failure.
    """
    if not is_safe_url(url):
        logger.warning(f"Skipping unsafe or invalid URL: {url}")
        return []

    logger.info(f"Fetching {url}...")
    lines = []
    
    for attempt in range(MAX_RETRIES):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=URL_TIMEOUT) as response:
                # 'utf-8-sig' handles BOM automatically
                data = response.read().decode('utf-8-sig', errors='ignore')
                for line in data.splitlines():
                    line = line.strip()
                    # Remove comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    # Remove inline comments (careful not to break URLs with fragments, though uncommon in lists)
                    if '#' in line:
                         # Only split if # is followed by space or end of line to avoid breaking complex URLs
                         # Simple heuristic: Split on first #
                        line = line.split('#')[0].strip()
                    if line:
                        lines.append(line)
            # If successful, break retry loop
            return lines
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                logger.warning(f"Error fetching {url}: {e}. Retrying ({attempt+1}/{MAX_RETRIES})...")
                time.sleep(2)
            else:
                logger.error(f"Failed to fetch {url} after {MAX_RETRIES} attempts: {e}")
    return lines

def parse_network_safe(line: str) -> Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """
    Safely parses a line into an ip_network object.
    1. Tries strict parsing.
    2. Tries parsing as a URL (extracting IP from hostname).
    3. Tries Regex extraction for IPv4 (handling pipe-delimited logs etc).
    """
    line = line.strip()
    if not line:
        return None
    
    # 1. Direct Parsing (Most common case: Clean IP lists)
    try:
        return ipaddress.ip_network(line, strict=False)
    except ValueError:
        pass

    # 2. Try parsing as a single address and convert to network
    try:
        addr = ipaddress.ip_address(line)
        return ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}", strict=False)
    except ValueError:
        pass

    # 3. Handle URLs (e.g. http://1.2.3.4/malware.exe)
    # This extracts the IP '1.2.3.4' from the URL.
    if '://' in line:
        try:
            parsed = urlparse(line)
            netloc = parsed.netloc
            
            # Cleanup brackets for IPv6 [::1]
            if netloc.startswith('[') and ']' in netloc:
                netloc = netloc.split(']')[0].strip('[')
            # Cleanup Port for IPv4 1.2.3.4:80
            elif ':' in netloc:
                # Be careful with IPv6 literals without brackets (rare in URLs but possible in raw data)
                # If it looks like IPv4 (3 dots), assume colon is port
                if netloc.count('.') == 3:
                    netloc = netloc.split(':')[0]
            
            addr = ipaddress.ip_address(netloc)
            return ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}", strict=False)
        except ValueError:
            pass # Domain name URLs will fail here, which is expected

    # 4. Regex Fallback (e.g. "ASN | 1.2.3.4 | Date")
    # Finds the first valid IPv4 string in the line
    match = IPV4_REGEX.search(line)
    if match:
        candidate = match.group(0)
        try:
            return ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            pass

    return None

def _get_key_from_addr(addr: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> int:
    """
    Returns a hashable key for bucketing from an address object.
    IPv4: First byte (0-255)
    IPv6: First 2 bytes (0-65535) for better distribution
    """
    if addr.version == 4:
        return addr.packed[0]
    else:
        # For IPv6, use first 2 bytes (big-endian) to create more buckets
        return int.from_bytes(addr.packed[:2], 'big')

def _worker_process_chunk(chunk: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]], 
                          global_excl: Optional[List] = None, 
                          buckets: Optional[Dict] = None) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """
    Worker function executed in parallel processes.
    Processes a specific chunk of networks against the exclusion buckets.
    Uses globals if arguments are None (Multiprocessing case).
    """
    try:
        results = []
        
        # If running in MP pool, use the globals set by initializer
        if global_excl is None:
            global_excl = WORKER_GLOBAL_EXCL
        if buckets is None:
            buckets = WORKER_BUCKETS
        
        for net in chunk:
            # 1. Determine which exclusions apply
            
            # Optimization: 
            # IPv4 buckets are /8 aligned (first byte). IPv6 buckets are /16 aligned (first 2 bytes).
            # If the network is smaller than or equal to the bucket size (larger prefixlen), it strictly fits in one bucket.
            # This avoids the expensive net[-1] calculation for the vast majority of subnets.
            is_single_bucket = (net.version == 4 and net.prefixlen >= 8) or \
                               (net.version == 6 and net.prefixlen >= 16)

            relevant_iterables = [global_excl]

            if is_single_bucket:
                # Fast path: Key calculation is cheap
                bucket_key = _get_key_from_addr(net.network_address)
                bucket_items = buckets.get(bucket_key)
                if bucket_items:
                    relevant_iterables.append(bucket_items)
            else:
                # Slow path: Network might span multiple buckets (e.g. /0, /4, /12)
                # We must calculate the range of keys it covers
                start_key = _get_key_from_addr(net.network_address)
                # net[-1] is somewhat expensive (creates new Address object), but necessary here to handle large blocks
                end_key = _get_key_from_addr(net[-1])

                if start_key == end_key:
                    bucket_items = buckets.get(start_key)
                    if bucket_items:
                        relevant_iterables.append(bucket_items)
                else:
                    # Iterate all buckets this network covers
                    for k in range(start_key, end_key + 1):
                        bucket_items = buckets.get(k)
                        if bucket_items:
                            relevant_iterables.append(bucket_items)
            
            # itertools.chain.from_iterable is efficient for combining multiple lists
            relevant_exclusions = itertools.chain.from_iterable(relevant_iterables)

            # 2. Process this single network
            current_fragments = [net]
            
            for exc in relevant_exclusions:
                if not current_fragments:
                    break
                    
                next_fragments = []
                for fragment in current_fragments:
                    # Fast Overlap Check
                    if not fragment.overlaps(exc):
                        next_fragments.append(fragment)
                        continue

                    # Case A: Fragment is fully inside exclusion (or equal) -> Remove it completely
                    if fragment.subnet_of(exc):
                        continue
                    
                    # Case B: Exclusion is inside fragment -> Shred it
                    elif exc.subnet_of(fragment):
                        next_fragments.extend(fragment.address_exclude(exc))
                    
                    # Case C: Partial overlap is impossible for strictly defined CIDR blocks
                    # that are not subnet/supernet of each other.
                    # We default to keeping the fragment if it survived overlap check 
                    # but failed containment checks (should logically be unreachable).
                    else:
                        next_fragments.append(fragment)
                
                current_fragments = next_fragments
            
            results.extend(current_fragments)
        return results
    except Exception as e:
        # Use print here as logging might not be configured in worker process
        print(f"CRITICAL ERROR in worker processing chunk: {e}")
        return []

def apply_exclusions(networks: List, exclusions: List, use_mp: bool = True) -> List:
    """
    Applies exclusion logic to a list of networks using Multiprocessing and Indexing.
    'networks' and 'exclusions' must be of the same IP version (v4 or v6).
    """
    if not exclusions:
        # Just collapse and return if no exclusions
        return list(ipaddress.collapse_addresses(networks))

    start_t = time.time()
    
    # 1. Optimize Exclusions
    # Collapsing here reduces the number of exclusion checks significantly
    collapsed_exclusions = list(ipaddress.collapse_addresses(exclusions))
    
    # 2. Optimize Networks
    # Collapsing input networks is also crucial for performance before processing
    collapsed_networks = list(ipaddress.collapse_addresses(networks))
    
    initial_count = len(collapsed_networks)
    logger.info(f"    Applying {len(collapsed_exclusions)} exclusions to {initial_count} networks...")

    # 3. Index Exclusions (Bucketing)
    global_excl = [] 
    buckets = {}     
    
    for exc in collapsed_exclusions:
        start_key = _get_key_from_addr(exc.network_address)
        
        # Calculate key for the last address directly
        end_key = _get_key_from_addr(exc[-1])
        
        if start_key == end_key:
            # Fits within one bucket
            if start_key not in buckets:
                buckets[start_key] = []
            buckets[start_key].append(exc)
        else:
            # Spans buckets
            global_excl.append(exc)

    # 4. Multiprocessing
    max_workers = os.cpu_count() or 4
    
    if len(collapsed_networks) < MIN_NETWORKS_FOR_MP or not use_mp:
        logger.info(f"    Dataset small ({len(collapsed_networks)}) or MP disabled, running inline...")
        return _worker_process_chunk(collapsed_networks, global_excl=global_excl, buckets=buckets)

    # Calculate chunks - optimized for load balancing
    # Using more chunks per worker helps balance heavy/light chunks
    total_chunks = max_workers * CHUNKS_PER_WORKER
    chunk_size = max(1, len(collapsed_networks) // total_chunks)
    
    chunks = [collapsed_networks[i:i + chunk_size] for i in range(0, len(collapsed_networks), chunk_size)]
    actual_workers = min(max_workers, len(chunks))
    
    logger.info(f"    Starting {actual_workers} processes (chunk_size={chunk_size})...")
    
    final_networks = []
    
    # Pass initializer to set globals in workers
    with concurrent.futures.ProcessPoolExecutor(
        max_workers=actual_workers,
        max_tasks_per_child=MAX_TASKS_PER_CHILD,
        initializer=init_worker, 
        initargs=(global_excl, buckets)
    ) as executor:
        
        futures = []
        for chunk in chunks:
            # We do NOT pass global_excl/buckets here, relying on initializer
            futures.append(executor.submit(_worker_process_chunk, chunk))
        
        for future in concurrent.futures.as_completed(futures):
            try:
                final_networks.extend(future.result())
            except Exception as e:
                logger.error(f"    CRITICAL ERROR in worker process: {e}")

    final_count = len(final_networks)
    elapsed = time.time() - start_t
    
    if final_count != initial_count:
        logger.info(f"    -> Exclusions applied in {elapsed:.2f}s. Count changed: {initial_count} -> {final_count}")
    else:
        logger.info(f"    -> Checks complete in {elapsed:.2f}s. No changes.")
        
    return final_networks

def get_ip_list(url_file: str, exclusion_file: str, use_mp: bool = True) -> Tuple[Set, Dict]:
    urls = []
    source_stats = {}
    
    # Raw collection buckets
    raw_v4 = []
    raw_v6 = []

    logger.info(f"  Reading Source File: {url_file}")
    try:
        with open(url_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        logger.error(f"  ERROR: File not found: {url_file}")
        return set(), source_stats

    # 1. Parallel Fetching
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_FETCH_WORKERS) as executor:
        future_to_url = {executor.submit(fetch_url_lines, url): url for url in urls}
        
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            lines = future.result()
            count_for_source = 0
            
            for line in lines:
                net = parse_network_safe(line)
                if net:
                    if net.version == 4:
                        raw_v4.append(net)
                    else:
                        raw_v6.append(net)
                    count_for_source += 1
            
            source_stats[url] = count_for_source

    # 2. Load Exclusions
    excl_v4 = []
    excl_v6 = []
    
    if os.path.exists(exclusion_file):
        logger.info(f"  Reading Exclusion File: {exclusion_file}")
        local_lines = []
        remote_urls = []
        
        with open(exclusion_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '#' in line:
                    line = line.split('#')[0].strip()
                
                if line.lower().startswith(('http://', 'https://')):
                    remote_urls.append(line)
                else:
                    local_lines.append(line)

        all_exclusion_lines = list(local_lines)

        if remote_urls:
            logger.info(f"    Found {len(remote_urls)} remote exclusion lists. Fetching...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_FETCH_WORKERS//2) as executor:
                future_to_url = {executor.submit(fetch_url_lines, url): url for url in remote_urls}
                for future in concurrent.futures.as_completed(future_to_url):
                    try:
                        fetched_lines = future.result()
                        all_exclusion_lines.extend(fetched_lines)
                    except Exception as e:
                        logger.warning(f"    WARNING: Failed to fetch exclusion list: {e}")

        logger.info(f"    Parsing {len(all_exclusion_lines)} potential exclusion rules...")
        for line in all_exclusion_lines:
            net = parse_network_safe(line)
            if net:
                if net.version == 4:
                    excl_v4.append(net)
                else:
                    excl_v6.append(net)
    else:
        logger.info(f"  NOTICE: No exclusion file found at {exclusion_file}")

    logger.info(f"  Loaded Exclusions: {len(excl_v4)} IPv4, {len(excl_v6)} IPv6")

    # 3. Process Exclusions & Flatten
    logger.info(f"  Processing {len(raw_v4)} IPv4 and {len(raw_v6)} IPv6 objects against exclusions...")
    
    final_v4 = apply_exclusions(raw_v4, excl_v4, use_mp=use_mp)
    final_v6 = apply_exclusions(raw_v6, excl_v6, use_mp=use_mp)

    return set(final_v4 + final_v6), source_stats

def write_files(ip_set: Set, output_dir: str, merged_filename: str) -> Dict:
    v4_list = []
    v6_list = []

    for ip in ip_set:
        if ip.version == 6:
            v6_list.append(ip)
        else:
            v4_list.append(ip)

    logger.info(f"  Collapsing and optimizing output...")
    
    # Final collapse to ensure cleanliness after exclusions
    # This remains necessary as exclusion logic might fragment networks adjacent to each other
    collapsed_v4 = list(ipaddress.collapse_addresses(v4_list))
    collapsed_v6 = list(ipaddress.collapse_addresses(v6_list))

    ipv6_set = collapsed_v6
    network_set = []
    single_ip_set = []
    
    total_ipv4_addresses = 0
    cidr_breakdown = {}

    for ip in collapsed_v4:
        total_ipv4_addresses += ip.num_addresses
        prefix = str(ip.prefixlen)
        cidr_breakdown[prefix] = cidr_breakdown.get(prefix, 0) + 1

        if ip.prefixlen == 32:
             single_ip_set.append(ip)
        else:
            network_set.append(ip)

    # Sorting
    ipv6_set.sort(key=lambda x: (x.network_address, x.prefixlen))
    network_set.sort(key=lambda x: (x.network_address, x.prefixlen))
    single_ip_set.sort(key=lambda x: (x.network_address, x.prefixlen))
    
    full_list = ipv6_set + network_set + single_ip_set
    full_list.sort(key=lambda x: (x.version, x.network_address, x.prefixlen))

    def stringify(obj):
        if obj.version == 4 and obj.prefixlen == 32:
            return str(obj.network_address)
        if obj.version == 6 and obj.prefixlen == 128:
            return str(obj.network_address)
        return str(obj)

    os.makedirs(output_dir, exist_ok=True)

    with open(os.path.join(output_dir, 'ipv6.txt'), 'w') as f:
        f.writelines(stringify(ip) + '\n' for ip in ipv6_set)
            
    with open(os.path.join(output_dir, 'networks.txt'), 'w') as f:
        f.writelines(stringify(ip) + '\n' for ip in network_set)

    with open(os.path.join(output_dir, 'single_ips.txt'), 'w') as f:
        f.writelines(stringify(ip) + '\n' for ip in single_ip_set)

    with open(merged_filename, 'w') as f:
        f.writelines(stringify(ip) + '\n' for ip in full_list)
    
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
    # Logging Configuration
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Determine the directory where the script is located
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

    start_time = time.time()
    dashboard_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "execution_duration_seconds": 0,
        "inbound": {},
        "outbound": {}
    }

    # Define paths relative to the script location
    inbound_url_file = os.path.join(BASE_DIR, 'tables', 'inbound', 'urltable_inbound')
    inbound_exclusion_file = os.path.join(BASE_DIR, 'tables', 'inbound', 'urlexclusion_inbound')
    inbound_output_dir = os.path.join(BASE_DIR, 'tables', 'inbound')
    inbound_merged_file = os.path.join(BASE_DIR, 'inbound.txt')

    outbound_url_file = os.path.join(BASE_DIR, 'tables', 'outbound', 'urltable_outbound')
    outbound_exclusion_file = os.path.join(BASE_DIR, 'tables', 'outbound', 'urlexclusion_outbound')
    outbound_output_dir = os.path.join(BASE_DIR, 'tables', 'outbound')
    outbound_merged_file = os.path.join(BASE_DIR, 'outbound.txt')

    # Explicitly enable multiprocessing since the entry point is guarded
    use_mp = True

    # Process Inbound
    logger.info("Processing Inbound...")
    inbound_ips, inbound_sources = get_ip_list(inbound_url_file, inbound_exclusion_file, use_mp=use_mp)
    inbound_stats = write_files(inbound_ips, inbound_output_dir, inbound_merged_file)
    
    dashboard_data["inbound"] = {
        "sources": inbound_sources,
        "raw_total": sum(inbound_sources.values()),
        "unique_pre_collapse": len(inbound_ips),
        "stats": inbound_stats
    }

    # Process Outbound
    logger.info("\nProcessing Outbound...")
    outbound_ips, outbound_sources = get_ip_list(outbound_url_file, outbound_exclusion_file, use_mp=use_mp)
    outbound_stats = write_files(outbound_ips, outbound_output_dir, outbound_merged_file)

    dashboard_data["outbound"] = {
        "sources": outbound_sources,
        "raw_total": sum(outbound_sources.values()),
        "unique_pre_collapse": len(outbound_ips),
        "stats": outbound_stats
    }

    end_time = time.time()
    dashboard_data["execution_duration_seconds"] = round(end_time - start_time, 2)

    stats_dir = os.path.join(BASE_DIR, 'stats')
    os.makedirs(stats_dir, exist_ok=True)
    timestamp_str = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    
    with open(os.path.join(stats_dir, f"stats_{timestamp_str}.json"), 'w') as f:
        json.dump(dashboard_data, f, indent=4)
    
    with open(os.path.join(stats_dir, 'latest.json'), 'w') as f:
        json.dump(dashboard_data, f, indent=4)

    logger.info(f"\nUpdate complete in {dashboard_data['execution_duration_seconds']}s")

if __name__ == "__main__":
    main()
