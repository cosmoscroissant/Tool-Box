# Tool Box
## Requirements
- Python 3.10+
- IDA 9.2

## File Structure
hello.exe represents the samples downloaded by "Downloader". IDA_Files/ represents the files you downloaded from IDA. 0 is pseudo-C of sample's entry point.

## How-To
main.py will open a local Python server that presents visualization for IR analysis results and ASM footprint (IoC) results. Use same file names for .asm file and ir file, for example hello.asm and hello.txt.

```
1. view existing results
python3 main.py --results ./Data/Analytics/<file_name>

2. run both analyses together
python3 main.py --ir 'Data/Test-Data/' --asm 'Data/Test-Data/'

3. run IR pattern analysis (minutes)
python3 main.py --ir 'Data/Test-Data/'

4. run IR pattern analysis in thorough mode (hours)
python3 main.py --ir 'Data/Test-Data/' --thorough

5. run ASM footprint sniff
python3 main.py --asm 'Data/Test-Data/'
```

## Data
Hello is a Go program that prints "hello", hello1 and hello2 are identical.

WannaCry are two different 2017 WannaCry files, wannacry.exe (24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c) and tasksche.exe (24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c).