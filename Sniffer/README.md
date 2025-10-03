# Sniffer
## ASM Footprint
asm_footprint_sniffer.py generates report containing hashes of the files and IoCs.
- hashes: IDA generate hashes
- protocols_full: well formed URLs
- urls: malformed or partial URLs
- domains: standalone domain names without protocols
- files
    - executable: exe, dll, scr, pif, com
    - sript: bat, cmd, vbs, js, ps1, sh, php
    - archives: zip, rar, 7z, jar
- main_patterns: functions and variables names that includes "main"
- ssh_patterns: referenced SSH client
- openssh_full: catches identity spoofing (complete email address)
- operational_files: files that carried out the operation
- dependency_paths: dependency in used

f.y.i. asm_footprint_sniffer_lib.txt is for blacklisting URLs that are unrelated to samples, such as hex-rays.com.

### How-To
`python3 asm_footprint_sniffer.py <file_path> -o report.txt`

`python3 asm_footprint_sniffer.py <directory_path> -r -o report.txt`

`python3 asm_footprint_sniffer.py <file_path> -o report.json -f json`

`python3 asm_footprint_sniffer.py <directory_path> -r -o report.json -f json`