import os
import json
import glob
import shutil
from datetime import datetime, timedelta

def find_value(data, target_key):
    """
    Recursively searches for a key in a nested dictionary or list.
    Returns the value if found, otherwise None.
    """
    if isinstance(data, dict):
        for key, value in data.items():
            if key == target_key:
                return value
            found = find_value(value, target_key)
            if found is not None:
                return found
    elif isinstance(data, list):
        for item in data:
            found = find_value(item, target_key)
            if found is not None:
                return found
    return None

def generate_history():
    """
    Parses stats json files to generate a history of total_ipv4_addresses_covered
    for the last 3 months. 
    - Scans both 'stats/' and 'stats/archived/' to build the full history.
    - Moves processed files from 'stats/' to 'stats/archived/'.
    - Only keeps one entry (the latest) per day in the output JSON.
    """
    # Configuration
    stats_dir = 'stats'
    archive_dir = os.path.join(stats_dir, 'archived')
    output_file = os.path.join(stats_dir, 'history.json')
    ignored_files = {'latest.json', 'history.json'}
    
    # Ensure archive directory exists
    if not os.path.exists(archive_dir):
        os.makedirs(archive_dir)

    # Calculate cutoff date (90 days ago)
    cutoff_date = datetime.now() - timedelta(days=90)
    
    # Dictionary to ensure unique days: key='YYYY-MM-DD', value=record_dict
    daily_records = {}
    files_to_archive = []

    # 1. Find files in stats/ (New files to process AND archive)
    root_files = glob.glob(os.path.join(stats_dir, '*.json'))
    
    # 2. Find files in stats/archived/ (Old files to process for history)
    archived_files = glob.glob(os.path.join(archive_dir, '*.json'))
    
    # Combine lists
    all_files = root_files + archived_files
    
    # Sort files by name ensures chronological order.
    # This allows us to overwrite earlier records for the same day with later ones.
    all_files.sort()
    
    print(f"Scanning {len(all_files)} files (New: {len(root_files)}, Archived: {len(archived_files)})...")

    for filepath in all_files:
        filename = os.path.basename(filepath)
        
        # Explicitly ignore specific config/output files
        if filename in ignored_files:
            continue

        # Check if this file is a candidate for archiving (is it in the root folder?)
        # We check this based on the directory of the current filepath
        is_in_root = os.path.abspath(os.path.dirname(filepath)) == os.path.abspath(stats_dir)
        
        # We only want to archive "stats_" files, just in case other JSONs exist
        if is_in_root and filename.startswith("stats_"):
            files_to_archive.append(filepath)

        try:
            # 3. Extract date from filename
            # Handles 'stats_YYYYMMDD_HHMMSS.json' format
            clean_name = filename.replace('stats_', '').replace('.json', '')
            
            try:
                file_date = datetime.strptime(clean_name, '%Y%m%d_%H%M%S')
            except ValueError:
                # Silently skip files that don't match the date pattern
                continue
            
            # 4. Filter for last 3 months
            if file_date < cutoff_date:
                continue

            # 5. Read JSON content
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 6. Extract the specific metric dynamically
            ipv4_count = find_value(data, 'total_ipv4_addresses_covered')
            
            if ipv4_count is not None:
                day_key = file_date.strftime('%Y-%m-%d')
                
                # Store/Update record for this day
                daily_records[day_key] = {
                    'date': file_date.isoformat(),
                    'timestamp': file_date.timestamp(),
                    'total_ipv4_addresses_covered': ipv4_count
                }
            else:
                print(f"Warning: Metric not found in {filename}")

        except json.JSONDecodeError:
            print(f"Skipping file {filename} (Invalid JSON)")
        except Exception as e:
            print(f"Error processing {filename}: {e}")

    # 7. Convert dictionary values to list and sort
    history_data = list(daily_records.values())
    history_data.sort(key=lambda x: x['date'])

    # 8. Write to output JSON file
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(history_data, f, indent=4)

    print(f"\nSuccess! Generated '{output_file}' with {len(history_data)} unique daily records.")

    # 9. Archive files
    if files_to_archive:
        print(f"Archiving {len(files_to_archive)} files to '{archive_dir}'...")
        for filepath in files_to_archive:
            try:
                shutil.move(filepath, archive_dir)
            except Exception as e:
                print(f"Error moving {os.path.basename(filepath)}: {e}")
        print("Archiving complete.")
    else:
        print("No new files to archive.")

if __name__ == "__main__":
    if not os.path.exists('stats'):
        print("Error: 'stats' directory not found. Please run this script from the root of your repository.")
    else:
        generate_history()