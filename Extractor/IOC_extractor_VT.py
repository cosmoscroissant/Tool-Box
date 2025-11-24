import time
import os
import traceback

from src.GetTime.ioc_get_time import *
from src.Constant.ioc_constants import *
from src.Logger.ioc_logger import *
from src.Loader.ioc_loader import *
from src.WebDriver.ioc_webdrive import *
from src.VirusTotal.ioc_virustotal import *
from src.Generator.ioc_generator import *

def save_hash(hash_val):
    if not os.path.exists(HASHES_FILE):
        with open(HASHES_FILE, 'w') as f:
            f.write("# VirusTotal Malware Hashes\n")
    
    with open(HASHES_FILE, 'a') as f:
        f.write(f"{hash_val}\n")

def save_skip_fail_hash(hash_val):
    if not os.path.exists(SKIP_FAIL_FILE):
        with open(SKIP_FAIL_FILE, 'w') as f:
            f.write("# VirusTotal Malware Hashes - Skipped or Failed\n")
    
    with open(SKIP_FAIL_FILE, 'a') as f:
        f.write(f"{hash_val}\n")

def format_bullets(text):
    if text == "Not Found!":
        return text
    lines = [line.strip() for line in text.split('\n') if line.strip()]
    if not lines:
        return "Not Found!"
    return '\n'.join([f"* {line}" for line in lines])

def save_ioc(ioc_data):
    if not os.path.exists(IOC_FILE):
        with open(IOC_FILE, 'w') as f:
            f.write("# VirusTotal Malware IOC Data\n\n")
    
    with open(IOC_FILE, 'a') as f:
        f.write(f"\n{'='*80}\n")
        f.write(f"HASH: {ioc_data['hash']}\n")
        f.write(f"TIMESTAMP: {ioc_data['timestamp']}\n")
        f.write(f"VENDOR DETECTIONS: {ioc_data['vendor_detections']}\n")
        f.write(f"{'='*80}\n\n")
        f.write(f"CALLS HIGHLIGHTED:\n{format_bullets(ioc_data['calls_highlighted'])}\n\n")
        f.write(f"COMMAND EXECUTIONS:\n{format_bullets(ioc_data['command_executions'])}\n\n")
        f.write(f"FILES OPENED:\n{format_bullets(ioc_data['files_opened'])}\n\n")
        f.write(f"FILES WRITTEN:\n{format_bullets(ioc_data['files_written'])}\n\n")
        f.write(f"FILES DELETED:\n{format_bullets(ioc_data['files_deleted'])}\n\n")
        f.write(f"FILES COPIED:\n{format_bullets(ioc_data['files_copied'])}\n\n")
        f.write(f"FILES ATTRIBUTE CHANGED:\n{format_bullets(ioc_data['files_attribute_changed'])}\n\n")
        f.write(f"FILES DROPPED:\n{format_bullets(ioc_data['files_dropped'])}\n\n")
        f.write(f"IDS ALERTS:\n{format_bullets(ioc_data['ids_alerts'])}\n\n")
        f.write(f"PROCESSES CREATED:\n{format_bullets(ioc_data['processes_created'])}\n\n")
        f.write(f"PROCESSES TERMINATED:\n{format_bullets(ioc_data['processes_terminated'])}\n\n")
        f.write(f"PROCESSES KILLED:\n{format_bullets(ioc_data['processes_killed'])}\n\n")
        f.write(f"PROCESSES INJECTED:\n{format_bullets(ioc_data['processes_injected'])}\n\n")
        f.write(f"PROCESSES TREE:\n{format_bullets(ioc_data['processes_tree'])}\n\n")
        f.write(f"SERVICES OPENED:\n{format_bullets(ioc_data['services_opened'])}\n\n")
        f.write(f"SERVICES CREATED:\n{format_bullets(ioc_data['services_created'])}\n\n")
        f.write(f"SERVICES STARTED:\n{format_bullets(ioc_data['services_started'])}\n\n")
        f.write(f"SERVICES STOPPED:\n{format_bullets(ioc_data['services_stopped'])}\n\n")
        f.write(f"SERVICES DELETED:\n{format_bullets(ioc_data['services_deleted'])}\n\n")
        f.write(f"MUTEXES OPENED:\n{format_bullets(ioc_data['mutexes_opened'])}\n\n")
        f.write(f"MUTEXES CREATED:\n{format_bullets(ioc_data['mutexes_created'])}\n\n")
        f.write(f"SIGNALS OBSERVED:\n{format_bullets(ioc_data['signals_observed'])}\n\n")
        f.write(f"MODULES LOADED:\n{format_bullets(ioc_data['modules_loaded'])}\n\n")
        f.write(f"REGISTRY KEYS OPENED:\n{format_bullets(ioc_data['registry_keys_opened'])}\n\n")
        f.write(f"REGISTRY KEYS SET:\n{format_bullets(ioc_data['registry_keys_set'])}\n\n")
        f.write(f"NETWORK COMMUNICATION:\n{format_bullets(ioc_data['network_communication'])}\n\n")
        f.write(f"HTTP REQUESTS:\n{format_bullets(ioc_data['http_requests'])}\n\n")
        f.write(f"DNS RESOLUTIONS:\n{format_bullets(ioc_data['dns_resolutions'])}\n\n")
        f.write(f"IP TRAFFIC:\n{format_bullets(ioc_data['ip_traffic'])}\n\n")
        f.write(f"MITRE ATTACK TECHNIQUES:\n{format_bullets(ioc_data['mitre_attack_techniques'])}\n\n")
        f.write(f"SIGNATURE MATCHES:\n{format_bullets(ioc_data['signature_matches'])}\n\n")
        f.write(f"BEHAVIOR SIMILARITY HASHES:\n{format_bullets(ioc_data['behavior_similarity_hashes'])}\n\n")
        f.write(f"WINDOWS SEARCHED:\n{format_bullets(ioc_data['windows_searched'])}\n\n")
        f.write(f"WINDOWS HIDDEN:\n{format_bullets(ioc_data['windows_hidden'])}\n\n")
        f.write(f"CRYPTO ALGORITHMS:\n{format_bullets(ioc_data['crypto_algorithms'])}\n\n")
        f.write(f"CRYPTO KEYS:\n{format_bullets(ioc_data['crypto_keys'])}\n\n")
        f.write(f"TEXT DECODED:\n{format_bullets(ioc_data['text_decoded'])}\n\n")
        f.write(f"TEXT HIGHLIGHTED:\n{format_bullets(ioc_data['text_highlighted'])}\n\n")
        f.write(f"MALWARE BEHAVIOR CATALOG:\n{format_bullets(ioc_data['malware_behavior_catalog'])}\n\n")
        f.write(f"CAPABILITIES:\n{format_bullets(ioc_data['capabilities'])}\n\n")
        f.write(f"{'='*80}\n")
    
    yara_rule = IOCGenerator.generate_yara_rule(ioc_data)
    if not os.path.exists(YARA_FILE):
        with open(YARA_FILE, 'w') as f:
            f.write("// VirusTotal Malware YARA Rules\n\n")
    
    with open(YARA_FILE, 'a') as f:
        f.write(yara_rule + '\n\n')

def ensure_files_exist():
    if not os.path.exists(HASHES_FILE):
        with open(HASHES_FILE, 'w') as f:
            f.write("# VirusTotal Malware Hashes\n")
        IOCLogger.log_message(f"Created {HASHES_FILE}")
    
    if not os.path.exists(IOC_FILE):
        with open(IOC_FILE, 'w') as f:
            f.write("# VirusTotal Malware IOC Data\n\n")
        IOCLogger.log_message(f"Created {IOC_FILE}")
    
    if not os.path.exists(YARA_FILE):
        with open(YARA_FILE, 'w') as f:
            f.write("// VirusTotal Malware YARA Rules\n\n")
        IOCLogger.log_message(f"Created {YARA_FILE}")
    
    if not os.path.exists(SKIP_FAIL_FILE):
        with open(SKIP_FAIL_FILE, 'w') as f:
            f.write("# VirusTotal Malware Hashes - Skipped or Failed\n")
        IOCLogger.log_message(f"Created {SKIP_FAIL_FILE}")

def run_scan():
    IOCLogger.log_message("\n" + "="*80)
    IOCLogger.log_message("STARTING COMPLETE SCAN CYCLE")
    IOCLogger.log_message("="*80 + "\n")
    
    ensure_files_exist()
    existing_hashes = IOCLoader.load_existing_hashes()
    
    # step 1
    IOCLogger.log_message("\n" + "="*80)
    IOCLogger.log_message("STEP 1: Scraping VirusTotal Search Page and Storing in STASH1")
    IOCLogger.log_message("="*80)
    stash1 = IOCVirusTotal.scrape_search_page()
    if not stash1:
        IOCLogger.log_message("No hashes found in STASH1 !")
        stash1 = []
    IOCLogger.log_message(f"STASH1 Collected: {len(stash1)} hashes\n")
    
    # step 2
    IOCLogger.log_message("="*80)
    IOCLogger.log_message("STEP 2: Accessing Behavior Page for STASH1 Hashes (touching pages)")
    IOCLogger.log_message("="*80)
    stash1_new = [h for h in stash1 if h not in existing_hashes]
    
    if stash1_new:
        for idx, hash_val in enumerate(stash1_new):
            IOCLogger.log_message(f"  [{idx+1}/{len(stash1_new)}] Touching: {hash_val}")
            try:
                IOCVirusTotal.fetch_behavior_page(hash_val)
                time.sleep(3)
            except Exception as e:
                IOCLogger.log_message(f"  Error touching {hash_val}: {e}")
                continue
        IOCLogger.log_message(f"Finished touching all {len(stash1_new)} behavior pages.\n")
    else:
        IOCLogger.log_message("All STASH1 Hashes Already Processed\n")
    
    # step 3
    IOCLogger.log_message("="*80)
    IOCLogger.log_message("STEP 3: Waiting 2 Minutes")
    IOCLogger.log_message("="*80)
    wait_time = 120
    for remaining in range(wait_time, 0, -1):
        if remaining % 30 == 0:
            IOCLogger.log_message(f"waiting {remaining} seconds remaining")
        time.sleep(1)
    IOCLogger.log_message("2 minutes elapsed\n")
    
    # step 4
    IOCLogger.log_message("="*80)
    IOCLogger.log_message("STEP 4: Scraping VirusTotal Search Page and Storing in STASH2")
    IOCLogger.log_message("="*80)
    stash2 = IOCVirusTotal.scrape_search_page()
    if not stash2:
        IOCLogger.log_message("No hashes found in STASH2 !")
        stash2 = []
    IOCLogger.log_message(f"STASH2 Collected: {len(stash2)} hashes\n")
    
    # step 5
    IOCLogger.log_message("="*80)
    IOCLogger.log_message("STEP 5: Accessing Behavior Pages for STASH2 Hashes (touching pages)")
    IOCLogger.log_message("="*80)
    stash2_new = [h for h in stash2 if h not in existing_hashes]
    
    if stash2_new:
        for idx, hash_val in enumerate(stash2_new):
            IOCLogger.log_message(f"  [{idx+1}/{len(stash2_new)}] Touching: {hash_val}")
            try:
                IOCVirusTotal.fetch_behavior_page(hash_val)
                time.sleep(3)
            except Exception as e:
                IOCLogger.log_message(f"  Error touching {hash_val}: {e}")
                continue
        IOCLogger.log_message(f"Finished touching all {len(stash2_new)} behavior pages\n")
    else:
        IOCLogger.log_message("All STASH2 hashes already processed!\n")
    
    # step 6
    IOCLogger.log_message("="*80)
    IOCLogger.log_message("STEP 6: Waiting 10 Minutes Before Extracting Behavior Data")
    IOCLogger.log_message("="*80)
    wait_time = 600
    for remaining in range(wait_time, 0, -1):
        if remaining % 60 == 0:
            IOCLogger.log_message(f"waiting {remaining} seconds remaining")
        time.sleep(1)
    IOCLogger.log_message("10 minutes elapsed, proceeding to extract behavior data\n")
    
    # step 7
    IOCLogger.log_message("="*80)
    IOCLogger.log_message("STEP 7: Extracting Behavior Data for All Hashes (STASH1 + STASH2)")
    IOCLogger.log_message("="*80)
    all_hashes_to_extract = stash1_new + stash2_new
    
    if not all_hashes_to_extract:
        IOCLogger.log_message("No new hashes to extract data from!")
    else:
        IOCLogger.log_message(f"Total Hashes to Extract: {len(all_hashes_to_extract)}\n")
        
        for idx, hash_val in enumerate(all_hashes_to_extract):
            IOCLogger.log_message(f"\n[{idx+1}/{len(all_hashes_to_extract)}] logging behavior data for hash: {hash_val}")
            ioc_data = IOCVirusTotal.scrape_behavior_page(hash_val)
            
            if ioc_data:
                save_hash(hash_val)
                save_ioc(ioc_data)
                IOCLogger.log_message(f"Successfully Saved Hash: {hash_val}\n")
            else:
                save_skip_fail_hash(hash_val)
                IOCLogger.log_message(f"Skipped or Failed for Hash: {hash_val}\n")
            
            time.sleep(3)
    
    IOCLogger.log_message("="*80)
    IOCLogger.log_message("SCAN CYCLE COMPLETE")
    IOCLogger.log_message("="*80)

if __name__ == "__main__":
    IOCLogger.log_message(f"extractor started at {IOCGetTime.get_utc_timestamp_long()}")
    
    try:
        run_scan()
        IOCLogger.log_message("Scan cycle completed successfully!")
    except KeyboardInterrupt:
        IOCLogger.log_message("\nScan interrupted by user!")
    except Exception as e:
        IOCLogger.log_message(f"Fatal Error: {e}")
        traceback.print_exc()
        exit(1)