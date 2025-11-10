import sys
import os
import subprocess
import time
import threading
import webbrowser
import http.server
import socketserver
import argparse
import json
import shutil

from pathlib import Path
from typing import Dict
from datetime import datetime

from Logger.stdout_logger import *
from Analyzer.ir_asm_cross_reference_analyzer import CrossReferenceModule
from IOC.constants import *

PORT = 8080

def copy_html_templates(run_dir: Path):
    html_template = Path(__file__).parent / 'Analyzer/ir_pattern_visualizer.html'
    if html_template.exists():
        shutil.copy(html_template, run_dir / 'ir_visualizer.html')
        print(f"copied IR pattern visualizer template")
    else:
        print(f"WARNING: IR pattern visualizer template not found at {html_template}")
    
    asm_footprint_template = Path(__file__).parent / 'Sniffer/asm_footprint_visualizer.html'
    if asm_footprint_template.exists():
        shutil.copy(asm_footprint_template, run_dir / 'asm_visualizer.html')
        print(f"copied ASM footprint visualizer template")
    else:
        print(f"WARNING: ASM footprint visualizer template not found at {asm_footprint_template}")

    cross_ref_template = Path(__file__).parent / 'Analyzer/ir_asm_cross_reference_visualizer.html'
    if cross_ref_template.exists():
        shutil.copy(cross_ref_template, run_dir / 'cross_visualizer.html')
        print(f"copied cross reference visualizer template")
    else:
        print(f"WARNING: cross reference visualizer template not found at {cross_ref_template}")
    
    ioc_template = Path(__file__).parent / 'Analyzer/IOC_visualizer.html'
    if ioc_template.exists():
        shutil.copy(ioc_template, run_dir / 'IOC_visualizer.html')
        print(f"copied IOC comparison visualizer template")
    else:
        print(f"WARNING: IOC comparison visualizer template not found at {ioc_template}")
    
    master_template = Path(__file__).parent / 'index_master.html'
    if master_template.exists():
        shutil.copy(master_template, run_dir / 'index.html')
        print(f"copied index template")
    else:
        print(f"WARNING: master index template not found at {master_template}")

def start_server(output_dir: Path):
    httpd = None
    server_ready = threading.Event()
    server_error = [None]
    
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(output_dir), **kwargs)
        
        def log_message(self, format, *args):
            pass
    
    def run_server():
        nonlocal httpd
        try:
            httpd = socketserver.TCPServer(("", PORT), Handler)
            httpd.allow_reuse_address = True
            server_ready.set()
            httpd.serve_forever()
        except OSError as e:
            server_error[0] = e
            server_ready.set()
    
    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    
    if not server_ready.wait(timeout=2.0):
        print(f"ERROR: server failed to start within timeout")
        return
    
    if server_error[0]:
        print(f"ERROR: could not start server")
        print(f"\n       {server_error[0]}")
        return
    
    webbrowser.open(f'http://localhost:{PORT}/index.html')
    
    try:
        print("press Ctrl+C to stop the server")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting Down")
        if httpd:
            httpd.shutdown()

def validate_analysis_results(output_dir: Path) -> Dict[str, bool]:
    ir_path = output_dir / 'results.json'
    asm_path = output_dir / 'asm_footprint_result.json'
    
    def is_valid_json(path: Path) -> bool:
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text())
            return isinstance(data, (dict, list)) and len(data) > 0
        except (json.JSONDecodeError, OSError):
            return False
    
    validation = {
        'ir_exists': ir_path.exists(),
        'ir_valid': False,
        'asm_exists': asm_path.exists(),
        'asm_valid': False
    }
    
    if validation['ir_exists']:
        try:
            ir_data = json.loads(ir_path.read_text())
            validation['ir_valid'] = (
                isinstance(ir_data, dict) and
                'semantic_enrichments' in ir_data and
                len(ir_data.get('files', [])) > 0
            )
        except (json.JSONDecodeError, OSError):
            pass
    
    if validation['asm_exists']:
        validation['asm_valid'] = is_valid_json(asm_path)
    
    return validation

def cleanup_failed_analysis(output_dir: Path):
    try:
        if output_dir.exists():
            files = list(output_dir.iterdir())
            if len(files) <= 1 and all(f.name.endswith('.txt') for f in files):
                print(f"cleaning up empty analysis directory: {output_dir}")
                shutil.rmtree(output_dir)
    except Exception as e:
        print(f"WARNING: could not cleanup directory: {e}")

def run_ir_analysis(ir_path: Path, output_dir: Path, thorough: bool = False) -> bool:
    print(f"\n{'='*80}")
    print("RUNNING IR PATTERN ANALYSIS")
    print(f"{'='*80}\n")
    
    cmd = ['python3', '-u', 'Analyzer/ir_pattern_analyzer.py', str(ir_path), str(output_dir)]
    if thorough:
        cmd.append('--thorough')
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            env={**os.environ, 'PYTHONUNBUFFERED': '1'}
        )
        
        for line in process.stdout:
            print(line, end='')
        
        process.wait()
        
        if process.returncode != 0:
            print(f"error: IR analysis failed with code {process.returncode}")
            return False
        
        print(f"\nIR analysis completed: {output_dir}")
        return True
        
    except FileNotFoundError:
        print("ERROR: ir_pattern_analyzer.py not found in current directory")
        return False
    except Exception as e:
        print(f"ERROR: Unexpected error: {e}")
        return False

def run_asm_sniffer(asm_path: Path, output_dir: Path, recursive: bool = True) -> bool:
    print(f"\n{'='*80}")
    print("RUNNING ASM SNIFFER")
    print(f"{'='*80}\n")
    
    temp_report = output_dir / 'asm_footprint_sniffer_report.txt'
    
    cmd = ['python3', '-u', 'Sniffer/asm_footprint_sniffer.py', str(asm_path), '-o', str(temp_report)]
    if recursive:
        cmd.append('-r')
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            env={**os.environ, 'PYTHONUNBUFFERED': '1'}
        )
        
        for line in process.stdout:
            print(line, end='')
        
        process.wait()
        
        if process.returncode != 0:
            print(f"WARNING: ASM sniffer encountered errors (code {process.returncode})")
        
        json_output = output_dir / 'asm_footprint_result.json'
        if json_output.exists():
            print(f"ASM sniffer completed: {json_output}\n")
            return True
        else:
            print("WARNING: asm_footprint_result.json not created")
            return False
            
    except FileNotFoundError:
        print("ERROR: asm_footprint_sniffer.py not found in current directory")
        return False
    except Exception as e:
        print(f"ERROR: Unexpected error: {e}")
        return False

def run_ioc_comparison(output_dir: Path) -> bool:
    print(f"\n{'='*80}")
    print("RUNNING IOC COMPARISON ANALYSIS")
    print(f"{'='*80}\n")
    
    ioc_text = IOC_Path
    asm_json = output_dir / 'asm_footprint_result.json'
    
    if not asm_json.exists():
        print("WARNING: asm_footprint_result.json not found, skipping IOC comparison")
        return False
    
    import os
    script_path = Path(__file__).parent / 'Analyzer' / 'IOC_analyzer.py'
    cmd = ['python3', '-u', str(script_path), str(ioc_text), str(asm_json), '-o', str(output_dir)]
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            env={**os.environ, 'PYTHONUNBUFFERED': '1'}
        )
        
        for line in process.stdout:
            print(line, end='')
        
        process.wait()
        
        if process.returncode != 0:
            print(f"WARNING: IOC comparison encountered errors (code {process.returncode})")
            return False
        
        json_files = list(output_dir.glob('*_vs_*.json'))
        if json_files:
            print(f"IOC comparison completed: {len(json_files)} result file(s) created\n")
            return True
        else:
            print("WARNING: no IOC comparison JSON files created")
            return False
            
    except FileNotFoundError:
        print("ERROR: Analyzer/IOC_analyzer.py not found")
        print("Make sure the IOC analyzer script is in the Analyzer/ directory!")
        return False
    except Exception as e:
        print(f"ERROR: unexpected error:\n{e}")
        return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--results', type=str, help='path to existing analysis results directory')
    parser.add_argument('--ir', type=str, help='path to IR files for analysis')
    parser.add_argument('--asm', type=str, help='path to ASM files for sniff')
    parser.add_argument('--thorough', action='store_true', help='use thorough mode for IR analysis')
    parser.add_argument('--no-recursive', action='store_true', help='disable recursive scanning for ASM')
    parser.add_argument('--name', type=str, help='default file name is timestamp')
    
    args = parser.parse_args()

    if args.results and (args.ir or args.asm):
        print("ERROR: cannot use --results with --ir or --asm")
        print("use --results to view existing results, OR --ir/--asm to run new analysis")
        sys.exit(1)
    
    if not args.results and not args.ir and not args.asm:
        print("ERROR: must specify either --results or --ir/--asm")
        parser.print_help()
        sys.exit(1)
    
    if args.results:
        results_path = Path(args.results)
        
        if not results_path.exists():
            print(f"ERROR: '{args.results}' does not exist")
            sys.exit(1)
        
        if not results_path.is_dir():
            print(f"ERROR: '{args.results}' is not a directory")
            sys.exit(1)
        
        required_files = ['results.json', 'graph_data.json']
        missing_files = [f for f in required_files if not (results_path / f).exists()]
        
        if missing_files:
            print(f"WARNING: missing required files in {results_path}:")
            for f in missing_files:
                print(f"  - {f}")
            print("IR Pattern Analysis may not work correctly")
        
        if not (results_path / 'asm_footprint_result.json').exists():
            print("Info: asm_footprint_result.json not found")
        
        output_dir = results_path
    
    else:
        if args.name:
            dir_name = args.name
            target_dir = Path('./Data/Analytics') / dir_name
            if target_dir.exists():
                print(f"WARNING: Directory '{dir_name}' already exists, using timestamp instead")
                dir_name = datetime.now().strftime('%Y%m%d_%H%M%S')
                target_dir = Path('./Data/Analytics') / dir_name
        else:
            dir_name = datetime.now().strftime('%Y%m%d_%H%M%S')
            target_dir = Path('./Data/Analytics') / dir_name
        
        output_dir = target_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        print(f"Created output directory: {output_dir}")

    log_file_path = output_dir / 'analysis_log.txt'
    logger = DualLogger(str(log_file_path))
    sys.stdout = logger
    sys.stderr = logger    
    analysis_success = False
    
    try:
        if args.ir:
            ir_path = Path(args.ir)
            if not ir_path.exists():
                print(f"ERROR: '{args.ir}' does not exist")
                sys.exit(1)

            success = run_ir_analysis(ir_path, output_dir, args.thorough)
            if not success:
                print("IR analysis failed")
                cleanup_failed_analysis(output_dir)
                sys.exit(1)
            analysis_success = True

        if args.asm:
            asm_path = Path(args.asm)
            if not asm_path.exists():
                print(f"ERROR: '{args.asm}' does not exist")
                sys.exit(1)
            
            if not (output_dir / 'results.json').exists():
                (output_dir / 'results.json').write_text(json.dumps({
                    'summary': {'total_files': 0, 'analyzed_files': 0, 'num_clusters': 0, 'noise_files': 0},
                    'clusters': {}, 'noise_files': [], 'files': [],
                    'similarity_matrix': [], 'features': [], 'feature_names': []
                }, indent=2))
                (output_dir / 'graph_data.json').write_text(json.dumps({}, indent=2))
            
            success = run_asm_sniffer(asm_path, output_dir, not args.no_recursive)
            if success:
                analysis_success = True
                ioc_success = run_ioc_comparison(output_dir)
                if ioc_success:
                    json_files = list(output_dir.glob('*_vs_*.json'))
                    main_json_files = [f for f in json_files if '_top5.json' not in f.name]
                    
                    if main_json_files:
                        shutil.copy(main_json_files[0], output_dir / 'ioc_comparison_report.json')
                        print(f"IOC comparison report created: ioc_comparison_report.json")
                    
                    top5_files = list(output_dir.glob('*_vs_*_top5.json'))
                    if top5_files:
                        shutil.copy(top5_files[0], output_dir / 'ioc_comparison_top5.json')
                        print(f"IOC top 5 report created: ioc_comparison_top5.json")
        
        if analysis_success:
            print(f"\n{'='*80}")
            print("RUNNING CROSS REFERENCE ANALYSIS")
            print(f"{'='*80}\n")

            validation = validate_analysis_results(output_dir)
            if validation['ir_valid'] and validation['asm_valid']:
                cross_ref = CrossReferenceModule()
                cross_ref.analyze(
                    str(output_dir / 'results.json'),
                    str(output_dir / 'asm_footprint_result.json')
                )
                cross_ref.export_cross_references(str(output_dir / 'cross_reference_analysis.json'))
            else:
                print("WARNING: cross reference analysis skipped (insufficient data)")
    
    finally:
        if hasattr(sys.stdout, 'close') and hasattr(sys.stdout, 'terminal'):
            sys.stdout.close()
            sys.stdout = sys.stdout.terminal
            sys.stderr = sys.stderr.terminal if hasattr(sys.stderr, 'terminal') else sys.stderr
    
    print(f"\n{'='*60}")
    print(f"Serving Results: {output_dir}")
    copy_html_templates(output_dir)
    
    print(f"\nStarting Web Server on {PORT}")
    print(f"Opening Browser to http://localhost:{PORT}/index.html")
    print("="*60)
    
    start_server(output_dir)

if __name__ == "__main__":
    main()