# IDA Python API
## ida_funcs
```
function_quantity = ida_funcs.get_func_qty()
function_count = 0
successful_functions = 0
summary_file = "ir_summary.txt"

for i in range(function_quantity):
    function_effective_address = ida_funcs.getn_func(i).start_ea
    func = ida_funcs.get_func(function_effective_address)

    if func:
        func_name = ida_funcs.get_func_name(function_effective_address)
```

1. get_func_qty

Get total number of functions in the program.

2. getn_func

Get pointer to function structure by number. 

3. get_func_name

Get function name.

## ida_hexrays
```
hex_ray_failure = ida_hexrays.hexrays_failure_t()
microcode_ranges = ida_hexrays.mba_ranges_t()
microcode_ranges.ranges.push_back(ida_range.range_t(func.start_ea, func.end_ea))
flags = ida_hexrays.DECOMP_WARNINGS
microcode_array = ida_hexrays.gen_microcode(microcode_ranges, hex_ray_failure, None, flags)

if microcode_array:
    visual_display = ida_hexrays.vd_printer_t()
    microcode_array._print(visual_display)
```
1. hexrays_failure_t

Handle hex rays error code.

2. mba_ranges_t

Define what memory address ranges to process.

3. push_back

push_back is API layered architected.

```
┌─ ida_hexrays (API) ────────────────────────────────┐
│  └── mba_ranges_t (configuration class)            │
│       └── ranges (data container): rangevec_t ────────┐
└────────────────────────────────────────────────────┘  │
                                                        │
┌─ ida_range (API)  ─────────────────────────────────┐  │
│  └── rangevec_t (specialized container class) ←───────┘
│    └── inherits from: rangevec_base_t (base class) │
│  └── rangevec_base_t (base container class)        │ 
│    └── push_back (method)                          │
└────────────────────────────────────────────────────┘
```

ida_hexrays
- mba_ranges_t is configuration class because it configures how the decompiler operates, it is the blueprint.
- microcode_ranges is configuration object, it is the instance.
- ranges is data container because it's the actual storage location for the data and it is part of a larger configuration object.

ida_range
- rangevec_t inherits functionality from rangevec_base_t (push_back).
- rangevec_base_t is the base class/parent class of rangevec_t.
- push_back adds function address ranges to the collection.

4. DECOMP_WARNINGS

Display warnings in the output window.

5. gen_microcode

Generate microcode of an arbitrary code snippet.

6. vd_printer_t

Handle visual display.

7. _print

_print is API layered architected, it prints out the visual display.

```
┌─ ida_hexrays (API) ────────────────────────────────┐
│  └── vd_printer_t (configuration class)            │
│       └── _print (member function)                 │
└────────────────────────────────────────────────────┘ 
```

## ida_range
### range_t
```
microcode_ranges.ranges.push_back(ida_range.range_t(func.start_ea, func.end_ea))
```
range_t is a continuous address range from start_ea (included) to end_ea (excluded).

## Referenced Documents
ida_ir_extractor.py is based of these documents.
- [-L#### name of the log file](https://docs.hex-rays.com/user-guide/configuration/command-line-switches)
- [IDAPython/examples/decompiler/vds13.py](https://github.com/HexRaysSA/IDAPython/blob/9.0sp1/examples/decompiler/vds13.py)
- [ida_funcs](https://python.docs.hex-rays.com/namespaceida__funcs.html)
    - [get_func_qty](https://python.docs.hex-rays.com/namespaceida__funcs.html#a05b428eb8dd6c9d993b8df1bfbf42ca5)
    - [getn_func](https://python.docs.hex-rays.com/namespaceida__funcs.html#a1e8f21feb68c1c73af655ab54672674e)
    - [get_func_name](https://python.docs.hex-rays.com/namespaceida__funcs.html#ad987bd43a75b4b0584bad764f1090e57)
- [ida_hexrays](https://python.docs.hex-rays.com/namespaceida__hexrays.html)
    - [hexrays_failure_t](https://python.docs.hex-rays.com/classida__hexrays_1_1hexrays__failure__t.html)
    - [mba_ranges_t](https://python.docs.hex-rays.com/classida__hexrays_1_1mba__ranges__t.html)
    - [ranges](https://python.docs.hex-rays.com/classida__hexrays_1_1mba__ranges__t.html#a8abe5f397550dc0da6ad0a9bb39a6358)
    - [DECOMP_WARNINGS](https://python.docs.hex-rays.com/namespaceida__hexrays.html#ad974fb393066e5d796f51dec0290396c)
    - [gen_microcode](https://python.docs.hex-rays.com/namespaceida__hexrays.html#a2257ed389d785f2af2949267383be896)
    - [vd_printer_t](https://python.docs.hex-rays.com/classida__hexrays_1_1vd__printer__t.html)
    - [_print](https://python.docs.hex-rays.com/classida__hexrays_1_1vd__printer__t.html#a5aee8ecca598270bfe1528b297fd62e0)
- [ida_range](https://python.docs.hex-rays.com/namespaceida__range.html)
    - [range_t](https://python.docs.hex-rays.com/classida__range_1_1range__t.html)
    - [rangevec_t](https://python.docs.hex-rays.com/classida__range_1_1rangevec__t.html)
    - [rangevec_base_t](https://python.docs.hex-rays.com/classida__range_1_1rangevec__base__t.htmlt)
- [Decompiler internals: microcode Ilfak Guilfanov](https://i.blackhat.com/us-18/Thu-August-9/us-18-Guilfanov-Decompiler-Internals-Microcode-wp.pdf)
- [Introduction to Hex- Rays decompilation internals](https://www.elastic.co/security-labs/introduction-to-hexrays-decompilation-internals)
    - "We can access the MBA (microcode block array) through the cfunc_t structure of a decompiled function with the MBA field."
        - MBA (microcode block array)