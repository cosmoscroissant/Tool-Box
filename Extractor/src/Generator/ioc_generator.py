class IOCGenerator:
    def generate_yara_rule(ioc_data):
        hash_val = ioc_data['hash'][:16]
        
        yara_rule = f"""
    rule malware_{hash_val}
    {{
        meta:
            hash = "{ioc_data['hash']}"
            timestamp = "{ioc_data['timestamp']}"
            vendor_detections = "{ioc_data['vendor_detections']}"
            files_opened = "{IOCGenerator.sanitize_string(ioc_data['files_opened'][:150])}"
            files_written = "{IOCGenerator.sanitize_string(ioc_data['files_written'][:150])}"
            files_deleted = "{IOCGenerator.sanitize_string(ioc_data['files_deleted'][:150])}"
            processes_created = "{IOCGenerator.sanitize_string(ioc_data['processes_created'][:150])}"
            modules_loaded = "{IOCGenerator.sanitize_string(ioc_data['modules_loaded'][:150])}"
            registry_keys_set = "{IOCGenerator.sanitize_string(ioc_data['registry_keys_set'][:150])}"
            mitre_attack_techniques = "{IOCGenerator.sanitize_string(ioc_data['mitre_attack_techniques'][:150])}"
            network_communication = "{IOCGenerator.sanitize_string(ioc_data['network_communication'][:150])}"
        
        strings:
            $hash = "{ioc_data['hash']}"
        
        condition:
            $hash
    }}
    """
        return yara_rule.strip()

    def sanitize_string(s):
        return s.replace('"', '\\"').replace('\n', ' ').replace('\r', '')
