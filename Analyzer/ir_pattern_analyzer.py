import argparse
from src.Analyzer.ir_analyzer import *

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='IR Structural Similarity Analyzer')
    parser.add_argument('path', help='path to IR files (IDA microcode .txt files)')
    parser.add_argument('output_dir', help='create file for results')
    parser.add_argument('--thorough', action='store_true', help='exhaustive dataflow analysis, slower')
    args = parser.parse_args()

    print("="*60)
    print("IR STRUCTURAL SIMILARITY ANALYZER")
    print("Purpose: analyze and cluster IDA microcode by structural patterns")
    print("Features: CFG/DFG analysis with 25 structural features")
    print("="*60 + "\n")

    analyzer = IRStructuralAnalyzer(output_dir=args.output_dir, thorough_mode=args.thorough)
    analyzer.analyze(args.path)