import re
import time

from selenium.webdriver.common.by import By

from ..Logger.ioc_logger import *
from ..WebDriver.ioc_webdrive import *
from ..Extractor.ioc_extractor import *

class IOCVirusTotal:
    def scrape_search_page():
        IOCLogger.log_message("Scraping VirusTotal Search Page")
        driver = None
        
        try:
            driver = IOCWebNev.create_webdriver()
            if not driver:
                return []
            
            IOCLogger.log_message(f"Navigating to: {VIRUSTOTAL_URL}")
            driver.get(VIRUSTOTAL_URL)
            
            IOCLogger.log_message("waiting 15 seconds for page to load")
            time.sleep(15)
            
            IOCLogger.log_message("extracting page content")
            body_text = driver.find_element(By.TAG_NAME, "body").text
            
            if not body_text:
                IOCLogger.log_message("No page content found!")
                return []
            
            IOCLogger.log_message(f"Page Content Length: {len(body_text)} characters")
            
            # look for SHA 256 hashes
            hash_pattern = r'([a-fA-F0-9]{64})'
            all_hashes = re.findall(hash_pattern, body_text)
            
            # remove duplicates while preserving order
            seen_hashes = set()
            unique_hashes = []
            for h in all_hashes:
                if h not in seen_hashes:
                    seen_hashes.add(h)
                    unique_hashes.append(h)
            
            IOCLogger.log_message(f"Found {len(unique_hashes)} Unique Hashes")
            
            if unique_hashes:
                IOCLogger.log_message(f"Sample Hashes: {unique_hashes[:3]}")
            
            return unique_hashes
        
        except Exception as e:
            IOCLogger.log_message(f"Error Scraping Search Page: {e}")
            traceback.print_exc()
            return []
        
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass

    def fetch_behavior_page(hash_val):
        IOCLogger.log_message(f"  Fetching Behavior Data for: {hash_val}")
        driver = None
        
        try:
            driver = IOCWebNev.create_webdriver()
            if not driver:
                return None
            
            behavior_url = f"https://www.virustotal.com/gui/file/{hash_val}/behavior"
            IOCLogger.log_message(f"  URL: {behavior_url}")
            
            driver.get(behavior_url)
            time.sleep(5)
            
            IOCLogger.log_message(f"  Fetched Successfully")
            return driver.find_element(By.TAG_NAME, "body").text
        
        except Exception as e:
            IOCLogger.log_message(f"  Error Fetching Behavior Page: {e}")
            return None
        
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass

    def scrape_behavior_page(hash_val):
        IOCLogger.log_message(f"  Scraping Behavior Data for: {hash_val}")
        
        try:
            body_text = IOCVirusTotal.fetch_behavior_page(hash_val)
            
            if not body_text:
                return None
            
            detection_match = re.search(r'(\d+)/(\d+)\s+security vendors flagged this file as malicious', body_text)
            if detection_match:
                detections = int(detection_match.group(1))
                total = detection_match.group(2)
                IOCLogger.log_message(f"  Vendor Detections for {hash_val}: {detections}/{total}")
                
                if detections == 0:
                    IOCLogger.log_message(f"  Vendor detections is 0/{total}, skipping!")
                    return None
            else:
                IOCLogger.log_message(f"  Could not find vendor detection ratio, skipping!")
                return None
            
            ioc_data = {
                'hash': hash_val,
                'vendor_detections': f"{detections}/{total}",
                'timestamp': IOCGetTime.get_utc_timestamp_long(),
                'calls_highlighted': IOCExtract.extract_section(body_text, ['Calls Highlighted', 'GetAdaptersAddresses'], ['Highlighted Text', 'Mode unknown']),
                'command_executions': IOCExtract.extract_section(body_text, ['Shell Commands', 'Process'], ['Processes Tree', 'Highlighted']),
                'files_opened': IOCExtract.extract_section(body_text, ['Files Opened'], ['Files Written', 'Files Deleted', 'Files Copied']),
                'files_written': IOCExtract.extract_section(body_text, ['Files Written'], ['Files Deleted', 'Files Copied', 'Files With Modified']),
                'files_deleted': IOCExtract.extract_section(body_text, ['Files Deleted'], ['Files Copied', 'Files With Modified', 'Files Dropped']),
                'files_copied': IOCExtract.extract_section(body_text, ['Files Copied'], ['Files With Modified', 'Files Dropped', 'Registry']),
                'files_attribute_changed': IOCExtract.extract_section(body_text, ['Files With Modified Attributes'], ['Files Dropped', 'Registry', 'Process']),
                'files_dropped': IOCExtract.extract_section(body_text, ['Files Dropped'], ['Registry Keys Opened', 'Registry', 'Processes']),
                'ids_alerts': IOCExtract.extract_section(body_text, ['IDS Rules'], ['Sigma Rules', 'Dropped Files']),
                'processes_created': IOCExtract.extract_section(body_text, ['Processes Created'], ['Processes Tree', 'Highlighted']),
                'processes_terminated': IOCExtract.extract_section(body_text, ['Processes terminated'], ['Processes killed', 'Highlighted']),
                'processes_killed': IOCExtract.extract_section(body_text, ['Processes killed'], ['Processes injected', 'Highlighted']),
                'processes_injected': IOCExtract.extract_section(body_text, ['Processes injected'], ['Services opened', 'Highlighted']),
                'processes_tree': IOCExtract.extract_section(body_text, ['Processes Tree'], ['Synchronization', 'Highlighted']),
                'services_opened': IOCExtract.extract_section(body_text, ['Services opened'], ['Services created', 'Highlighted']),
                'services_created': IOCExtract.extract_section(body_text, ['Services created'], ['Services started', 'Highlighted']),
                'services_started': IOCExtract.extract_section(body_text, ['Services started'], ['Services stopped', 'Highlighted']),
                'services_stopped': IOCExtract.extract_section(body_text, ['Services stopped'], ['Services deleted', 'Highlighted']),
                'services_deleted': IOCExtract.extract_section(body_text, ['Services deleted'], ['Services bound', 'Highlighted']),
                'mutexes_opened': IOCExtract.extract_section(body_text, ['Mutexes opened'], ['Mutexes created', 'Highlighted']),
                'mutexes_created': IOCExtract.extract_section(body_text, ['Mutexes Created'], ['Modules loaded', 'Runtime Modules', 'Highlighted']),
                'signals_observed': IOCExtract.extract_section(body_text, ['Signals observed'], ['Mutexes', 'Highlighted']),
                'modules_loaded': IOCExtract.extract_section(body_text, ['Runtime Modules', 'Modules loaded'], ['Highlighted actions', 'Calls Highlighted']),
                'registry_keys_opened': IOCExtract.extract_section(body_text, ['Registry Keys Opened'], ['Registry Keys Set', 'Gemini Summary']),
                'registry_keys_set': IOCExtract.extract_section(body_text, ['Registry Keys Set'], ['Gemini Summary', 'Processes Created', 'Process and service']),
                'network_communication': IOCExtract.extract_section(body_text, ['Network Communication'], ['Behavior Similarity', 'HTTP Requests', 'DNS Resolutions']),
                'http_requests': IOCExtract.extract_section(body_text, ['HTTP Requests'], ['DNS Resolutions', 'IP Traffic']),
                'dns_resolutions': IOCExtract.extract_section(body_text, ['DNS Resolutions'], ['IP Traffic', 'Behavior Similarity']),
                'ip_traffic': IOCExtract.extract_section(body_text, ['IP Traffic'], ['Behavior Similarity', 'CAPE Sandbox', 'VirusTotal']),
                'mitre_attack_techniques': IOCExtract.extract_section(body_text, ['MITRE ATT&CK Tactics and Techniques'], ['Malware Behavior Catalog', 'Low\nDiscovery']),
                'signature_matches': IOCExtract.extract_section(body_text, ['Crowdsourced IDS rules', 'Matches rule'], ['Network Communication', 'Memory Pattern']),
                'behavior_similarity_hashes': IOCExtract.extract_section(body_text, ['Behavior Similarity Hashes'], ['File system actions', 'Files Opened']),
                'windows_searched': IOCExtract.extract_section(body_text, ['Windows searched'], ['Windows hidden', 'Highlighted']),
                'windows_hidden': IOCExtract.extract_section(body_text, ['Windows hidden'], ['Highlighted', 'Download']),
                'crypto_algorithms': IOCExtract.extract_section(body_text, ['Crypto algorithms'], ['Crypto keys', 'Highlighted']),
                'crypto_keys': IOCExtract.extract_section(body_text, ['Crypto keys'], ['Crypto plaintext', 'Highlighted']),
                'text_decoded': IOCExtract.extract_section(body_text, ['Text decoded'], ['Highlighted text', 'Highlighted']),
                'text_highlighted': IOCExtract.extract_section(body_text, ['Highlighted Text'], ['Download Artifacts', 'MITRE']),
                'malware_behavior_catalog': IOCExtract.extract_section(body_text, ['Malware Behavior Catalog Tree'], ['Capabilities', 'Host-Interaction']),
                'capabilities': IOCExtract.extract_section(body_text, ['Capabilities'], ['Host-Interaction', 'Linking'])
            }
            
            return ioc_data
        
        except Exception as e:
            IOCLogger.log_message(f"Error Scraping Behavior Page for {hash_val}: {e}")
            traceback.print_exc()
            return None
        
    def check_virustotal(hash_val):
        IOCLogger.log_message(f"  checking VirusTotal for: {hash_val}")
        driver = None
        
        try:
            driver = IOCWebNev.create_webdriver()
            if not driver:
                return None
            
            vt_url = f"{VIRUSTOTAL_MalwareBazaar_URL}/{hash_val}"
            IOCLogger.log_message(f"  URL: {vt_url}")
            
            driver.get(vt_url)
            IOCLogger.log_message(f"  waiting 10 seconds for page to load")
            time.sleep(10)
            
            body_text = driver.find_element(By.TAG_NAME, "body").text
            
            detection_match = re.search(r'(\d+)/(\d+)\s+security vendors? flagged', body_text)
            if detection_match:
                detections = int(detection_match.group(1))
                total = detection_match.group(2)
                IOCLogger.log_message(f"  Found: {detections}/{total} detections")
                return {
                    'hash': hash_val,
                    'detections': detections,
                    'total': total,
                    'found': True
                }
            else:
                IOCLogger.log_message(f"  Hash not found or no detection data!")
                return {
                    'hash': hash_val,
                    'detections': 0,
                    'total': 0,
                    'found': False
                }
        
        except Exception as e:
            IOCLogger.log_message(f"  Error Checking VirusTotal: {e}")
            return None
        
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass

            
        