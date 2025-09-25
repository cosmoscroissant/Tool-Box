import os
import subprocess

sample_path = r"your_path_here"
ida_path = r"C:\Program Files\IDA Professional 9.2\ida.exe"

os.chdir(sample_path)

for filename in os.listdir(sample_path):
    if os.path.isfile(filename):
        print(f"generating files for {filename}")
        subprocess.run([ida_path, "-B", filename])
        print(f"files generated for {filename}")