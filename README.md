# Tool Box
## Requirements
- Python 3.10+
- IDA 9.2

## File Structure
hello.exe represents the samples downloaded by "Downloader". IDA_Files/ represents the files you downloaded from IDA. 0 is pseudo-C of sample's entry point.

### scripts only
```
Tool_Box/
├── sample_downloader.py
├── analysis_files_generator.py
├── pseudo_C_analyzer.py
├── asm_footprint_sniffer.py
└── sample/
    ├── hello.exe
    ├── ida_ir_progress_extractor.ps1
    ├── ida_ir_extractor.py
    └── IDA_Files/
        ├── 0 
        ├── hello.c
        └── ...
```

### scripts with output files
```
Tool_Box/
├── sample_downloader.py
├── analysis_files_generator.py
├── pseudo_C_analyzer.py
├── all_function.txt
├── missing_functions.txt
├── organized_code.txt
├── flow_chart.txt
├── asm_footprint_sniffer.py
├── report.txt
└── sample/
    ├── hello.exe (sample)
    ├── hello.i64
    ├── hello.asm
    ├── ida_ir_progress_extractor.ps1
    ├── ida_ir_extractor.py
    ├── ir.txt
    ├── ir_with_idainfo.txt
    ├── ir_summary.txt
    └── IDA_Files/
        ├── 0 
        ├── hello.c
        └── ...
```
