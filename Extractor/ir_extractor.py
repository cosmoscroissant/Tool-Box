import ida_funcs
import ida_range
import ida_hexrays
import time

def extract_ida_generated_microcode():
    start_time = time.time()
    start_timestamp = time.ctime()
    function_quantity = ida_funcs.get_func_qty()
    function_count = 0
    successful_functions = 0    
    summary_file = "ir_summary.txt"
    
    for i in range(function_quantity):
        function_effective_address = ida_funcs.getn_func(i).start_ea
        func = ida_funcs.get_func(function_effective_address)
        
        if func:
            func_name = ida_funcs.get_func_name(function_effective_address)            
            try:
                print(f"--- IR FOR {func_name} (0x{function_effective_address:08X}) ---")
                
                hex_ray_failure = ida_hexrays.hexrays_failure_t()
                microcode_ranges = ida_hexrays.mba_ranges_t()
                microcode_ranges.ranges.push_back(ida_range.range_t(func.start_ea, func.end_ea))
                flags = ida_hexrays.DECOMP_WARNINGS
                microcode_array = ida_hexrays.gen_microcode(microcode_ranges, hex_ray_failure, None, flags)
                
                if microcode_array:
                    visual_display = ida_hexrays.vd_printer_t()
                    microcode_array._print(visual_display)
                    print(f"--- END {func_name} ---")
                    print()
                    successful_functions += 1
                else:
                    error_message = hex_ray_failure.str if hex_ray_failure.str else "no IR generated"
                    print(f"FAILED {func_name} (0x{function_effective_address:08X}): {error_message}")
                    print()
                    
            except Exception as e:
                print(f"EXCEPTION {func_name} (0x{function_effective_address:08X}): {str(e)}")
                print()
                
            function_count += 1
    
    total_time = time.time() - start_time
    end_timestamp = time.ctime()
    
    summary_content = f"""=== SUMMARY ===
    Start Time: {start_timestamp}
    End Time: {end_timestamp}
    Total Duration Time: {total_time:.1f} seconds ({total_time/60:.1f} minutes)
    Total Functions Processed: {function_count}
    Successful: {successful_functions}
    Failed: {function_count - successful_functions}
    Success Rate: {(successful_functions*100/function_count):.1f}%
    """
    
    with open(summary_file, 'w') as f:
        f.write(summary_content)

def isolate_microcode(input_file, output_file):
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        microcode_start = "--- IR FOR"
        start_pos = content.find(microcode_start)
        
        if start_pos == -1:
            print(f"Error: '{microcode_start}' not found in the file")
            return False
        
        microcode_end = "--- END"
        end_pos = content.rfind(microcode_end)
        
        if end_pos == -1:
            print(f"Error: '{microcode_end}' not found in the file")
            return False
        
        if start_pos >= end_pos:
            print("Error: start appears after end")
            return False
        
        extracted_content = content[start_pos:end_pos + len(microcode_end)]
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(extracted_content)

        return True
        
    except FileNotFoundError:
        print(f"Error: input file '{input_file}' not found")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    extract_ida_generated_microcode()
    isolate_microcode("ir_with_idainfo.txt", "ir.txt")