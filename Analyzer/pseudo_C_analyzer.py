import os
import re
import sys
from pathlib import Path
import fnmatch

FUNCTION_PATTERNS = [
    # standard C function declarations: int funcName( or static void funcName(
    r'^\s*(?:__int64|int|void|char|unsigned|signed|static|extern|inline)\s+(?:\w+\s+)*(\w+(?:\s+\w+)*)\s*\(',
    # functions declared without opening brace on same line, complete function signatures on one line ending with )
    r'^\s*(?:__int64|int|void|char|unsigned|signed|static|extern|inline).*?(\w+(?:\s+\w+)*)\s*\([^)]*\)\s*$',
    # function declarations ending with { or end of line, function definitions with opening brace
    r'^\s*(?:__int64|int|void|char|unsigned|signed|static|extern|inline)\s+(\w+(?:\s+\w+)*)\s*\([^)]*\)\s*(?:{|\s*$)',
    # lines with just functionName() (no type prefix, no semicolon), function calls or declarations without explicit types
    r'^\s*(\w+(?:\s+\w+)*)\s*\([^)]*\)\s*$(?!.*;)',
    # int* funcName( or volatile char** funcName(, functions returning pointers
    r'^\s*(?:volatile\s+)?(?:\w+\s+\*+\s*)+(\w+(?:\s+\w+)*)\s*\(',
    # complex pointer declarations like volatile __int64 funcName(, functions with complex pointer return types
    r'^\s*\*+\s*(?:volatile\s+)?(?:__int\d*\s+)?\*+\s*(?:\w+\s+)*?(\w+(?:\s+\w+)*)\s*\(',
]

CALL_PATTERNS = [
    # basic function calls: functionName(
    r'(\w+)\s*\(',
    # return
    r'return\s+(\w+)\s*\(',
]

# use file 0 for starting point
def find_entry_point(functions):
    if not functions:
        return None
    return next(iter(functions))

"""
return actual function name [2]
bool __golang runtime_example
[0]     [1]         [2]  
"""
def clean_function_name(name):
    if ' ' in name:
        parts = name.split()
        if len(parts) >= 3 and (parts[0] in ['bool', 'int', 'void', 'char', '__int64', 'unsigned', 'signed'] or parts[1].startswith('__')):
            return ' '.join(parts[2:])
        elif len(parts) >= 2 and parts[0].startswith('__'):
            return ' '.join(parts[1:])
    return name

class FunctionExtractor:
    # main parser for codebase
    @staticmethod
    def extract_functions(content):
        functions = {}
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            stripped_line = line.strip()
            if not stripped_line or stripped_line.startswith(('//', '/*')):
                continue
            
            func_name = FunctionExtractor.find_function_name(stripped_line)
            if func_name and not FunctionExtractor.is_function_call(stripped_line):
                func_body = FunctionExtractor.extract_function_body(lines, i, func_name)
                if func_body and FunctionExtractor.is_valid_function(func_body, func_name):
                    functions[func_name] = func_body.strip()
        
        return functions
    
    # get single line of code from extract_functions, and returns function name
    @staticmethod
    def find_function_name(line):
        for pattern in FUNCTION_PATTERNS:
            match = re.search(pattern, line)
            if match:
                name = match.group(1).strip()                
                name = clean_function_name(name)
                
                if len(name.replace(' ', '')) > 1 and not name.replace(' ', '').isdigit():
                    return name
        return None
    
    # determin the line of code as function call or function definition
    @staticmethod
    def is_function_call(line):
        return (line.endswith(';') or any(op in line for op in ('=', '+=', '-=', '*=', '/=')))
    
    # make sure the extracted code is a complete code
    @staticmethod
    def is_valid_function(func_body, func_name):
        lines = func_body.strip().split('\n')
        if len(lines) < 2:
            return False
        
        func_name_parts = func_name.split()
        first_lines = '\n'.join(lines[:5])
        name_found = all(part in first_lines for part in func_name_parts) if len(func_name_parts) > 1 else func_name in first_lines
        
        if not name_found:
            return False
        
        open_braces = func_body.count('{')
        close_braces = func_body.count('}')
        
        return open_braces > 0 and open_braces == close_braces
    
    # extract function body start from function name
    @staticmethod
    def extract_function_body(lines, start_line, func_name):
        result = []
        brace_count = 0
        found_opening = False
        
        for j in range(max(0, start_line - 5), start_line):
            line = lines[j].strip()
            if line and (line.startswith('//') or any(part in line for part in func_name.split()) or 
                         any(kw in line.lower() for kw in {'void', 'int', 'char', '__int64', 'unsigned', 'volatile'})):
                result.append(lines[j])
            elif not line:
                result.append(lines[j])
        
        i = start_line
        while i < len(lines):
            line = lines[i]
            result.append(line)
            brace_count += line.count('{') - line.count('}')

            if '{' in line:
                found_opening = True
            
            if found_opening and brace_count == 0 and '}' in line:
                break
            
            i += 1
        
        return '\n'.join(result)

class LibraryManager:
    # load lib.txt file that erase noise by whitelisting function and blacklisting non-function
    @staticmethod
    def load_library(lib_file="lib.txt"):
        if not os.path.exists(lib_file):
            LibraryManager._create_empty_library(lib_file)
            return set(), set()
        
        functions, non_functions = set(), set()
        current_section = None
        
        try:
            with open(lib_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    if 'FUNCTIONS' in line.upper() and '===' in line:
                        current_section = 'FUNCTIONS'
                    elif 'NON-FUNCTIONS' in line.upper() and '===' in line:
                        current_section = 'NON-FUNCTIONS'
                    elif current_section == 'FUNCTIONS':
                        functions.add(line)
                    elif current_section == 'NON-FUNCTIONS':
                        non_functions.add(line)
        except:
            pass
        
        return functions, non_functions
    
    # use wildcard (runtime__*) to match with function names
    @staticmethod
    def matches_pattern(name, patterns):
        return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)

    # creat lib.txt if absent
    @staticmethod
    def _create_empty_library(lib_file):
        with open(lib_file, 'w', encoding='utf-8') as f:
            f.write("=== FUNCTIONS ===\n# add actual function names here, one per line\n\n"
                    "=== NON-FUNCTIONS ===\n# add non-function names here, one per line\n\n")
        print(f"created empty {lib_file}")

class CallGraphBuilder:
    """
    1. analyze function bodies to find function calls using CALL_PATTERNS
    2. create a map of which functions call which other functions
    3. build execution flow starting from entry point
    4. use depth-first traversal to order functions by call sequence
    5. return: execution order, missing functions, and call relationships
    """
    @staticmethod
    def build_call_graph(all_functions, start_func):
        call_map = {}
        missing_functions = set()
        compiled_patterns = [re.compile(pattern, re.IGNORECASE | re.MULTILINE) for pattern in CALL_PATTERNS]
        
        for name, body in all_functions.items():
            calls = set()
            
            for pattern in compiled_patterns:
                for match in pattern.finditer(body):
                    call_name = match.group(1)
                    
                    if CallGraphBuilder.is_valid_function_call(call_name, name, body, match.start()):
                        calls.add(call_name)
                        if call_name not in all_functions:
                            missing_functions.add(call_name)
            
            call_map[name] = list(calls)
        
        flow = []
        visited = set()
        
        def traverse(func_name, depth=0):
            if func_name in visited or depth > 100 or func_name not in all_functions:
                return
            
            visited.add(func_name)
            flow.append(func_name)
            
            for call in call_map.get(func_name, []):
                traverse(call, depth + 1)
        
        if start_func and start_func in all_functions:
            traverse(start_func)
        
        for func_name in all_functions:
            if func_name not in visited:
                traverse(func_name)
        
        return flow, missing_functions, call_map
    
    # verify the found pattern is function call
    @staticmethod
    def is_valid_function_call(call_name, func_name, body, match_pos):
        if call_name in func_name.split() and body[:match_pos].count('\n') < 10:
            return False
        
        context = body[max(0, match_pos-100):match_pos+50]
        
        exclusion_patterns = [
            f'{call_name} =',
            f'{call_name}++',
            f'{call_name}--',
            f'{call_name}[',
            f'{call_name}.',
            f'{call_name}->',
            f'&{call_name}',
            f'*{call_name}'
        ]
        
        return not any(pattern in context for pattern in exclusion_patterns)

class FunctionFilter:
    # apply non-function filter pattern (lib.txt)
    @staticmethod
    def filter_functions(all_functions, missing_functions, lib_functions, lib_non_functions):
        all_names = set(all_functions.keys()) | missing_functions
        classified = {name for name in all_names 
                     if (LibraryManager.matches_pattern(name, lib_functions) or 
                         LibraryManager.matches_pattern(name, lib_non_functions))}
        return all_names - classified

class FileManager:
    # create all_functions.txt
    @staticmethod
    def write_all_func_file(all_functions, missing_functions, lib_functions, lib_non_functions):
        new_names = FunctionFilter.filter_functions(all_functions, missing_functions, lib_functions, lib_non_functions)
        
        with open("all_functions.txt", "w", encoding='utf-8') as f:
            f.write("=== NEW FUNCTIONS TO CLASSIFY ===\n"
                   "(add these to lib.txt under FUNCTIONS or NON-FUNCTIONS)\n")
            
            if new_names:
                found = [name for name in new_names 
                        if name in all_functions and all_functions[name].strip()]
                missing = [name for name in new_names 
                          if name not in all_functions or not all_functions[name].strip()]
                
                if found:
                    f.write("=== FOUND FUNCTIONS ===\n")
                    cleaned_found = [clean_function_name(name) for name in sorted(found)]
                    f.write('\n'.join(cleaned_found) + '\n\n')
                if missing:
                    f.write("=== MISSING FUNCTIONS ===\n")
                    cleaned_missing = [clean_function_name(name) for name in sorted(missing)]
                    f.write('\n'.join(cleaned_missing) + '\n')
            else:
                f.write("all functions already classified in lib.txt\n")
        
        return len(new_names)

    # create organized_code.txt, flow_chart.txt, missing_functions.txt
    @staticmethod
    def write_output_files(flow, all_functions, call_map, missing_functions, lib_functions, lib_non_functions):
        filtered_names = FunctionFilter.filter_functions(all_functions, missing_functions,lib_functions, lib_non_functions)
        functions_for_output = {name: all_functions[name] for name in filtered_names if name in all_functions}
        
        with open("organized_code.txt", "w", encoding='utf-8') as f:
            f.write(f"=== ORGANIZED CODE ===\n"
                   f"total functions included: {len(functions_for_output)}\n\n"
                   f"=== FUNCTIONS IN EXECUTION ORDER ===\n\n")
            
            for func_name in flow:
                if func_name in functions_for_output:
                    display_name = clean_function_name(func_name)
                    f.write(f"// function name: {display_name}\n\n"
                            f"{functions_for_output[func_name]}\n\n{'='*50}\n\n")

        with open("flow_chart.txt", "w", encoding='utf-8') as f:
            f.write("=== FUNCTION CALL GRAPH ===\n")
            for func_name in flow:
                if func_name in filtered_names and func_name in call_map:
                    for call in call_map[func_name]:
                        if call in filtered_names:
                            f.write(f"{func_name} -> {call}\n")

        filtered_missing = filtered_names & missing_functions
        with open("missing_functions.txt", "w", encoding='utf-8') as f:
            f.write(f"=== MISSING FUNCTIONS ({len(filtered_missing)}) ===\n")
            if filtered_missing:
                f.write('\n'.join(sorted(filtered_missing)))
            else:
                f.write("All functions found!\n")

    # delete previously created files
    @staticmethod
    def delete_files(files):
        for file_path in files:
            try:
                os.remove(file_path)
            except (FileNotFoundError, OSError):
                continue

def main():
    if len(sys.argv) < 2:
        print("usage: python analyzer.py <directory>")
        sys.exit(1)

    FileManager.delete_files(["organized_code.txt", "flow_chart.txt", "missing_functions.txt", "all_functions.txt"])
    
    directory = Path(sys.argv[1])
    print(f"scanning directory: {directory}")
    
    start_file = directory / "0"
    if not start_file.exists():
        print("there is no file called 0")
        sys.exit(1)
    
    all_functions = {}
    
    with open(start_file, 'r', encoding='utf-8', errors='ignore') as f:
        file_0_functions = FunctionExtractor.extract_functions(f.read())
        all_functions.update(file_0_functions)
        print(f"processed file '0': found {len(file_0_functions)} functions, {list(file_0_functions.keys())}")
    
    start_func = find_entry_point(file_0_functions)
    print(f"entry point function: {start_func}")
    
    for file_path in directory.iterdir():
        if file_path.is_file() and file_path.name != "0":
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    functions = FunctionExtractor.extract_functions(f.read())
                    all_functions.update(functions)
            except:
                continue
    
    if not all_functions:
        return
    
    print(f"total functions found across all files: {len(all_functions)}")
    
    flow, missing_functions, call_map = CallGraphBuilder.build_call_graph(all_functions, start_func)
    lib_functions, lib_non_functions = LibraryManager.load_library()
    
    new_count = FileManager.write_all_func_file(all_functions, missing_functions, lib_functions, lib_non_functions)
    if new_count > 0:
        print(f"new functions to classify: {new_count}")
    
    FileManager.write_output_files(flow, all_functions, call_map, missing_functions, lib_functions, lib_non_functions)
    
    print("files created: organized_code.txt, flow_chart.txt, missing_functions.txt, all_functions.txt")

if __name__ == "__main__":
    main()