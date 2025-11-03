# Extractor
# ir_extractor.py
`first_op = parts[0].lower() if parts else 'N/O'`
- N/O: no operation

`pattern = f"E{edges}|O{tuple(sorted(opcode_sig))}"`
- E: edge
- O: opcode

`control_sig = f"L{loop_count}B{conditional_branches}C{call_count}U{unconditional_jumps}S{switch_count}K{block_count}"`
- L: loop
- B: branche
- C: call
- U: unconditional jump
- S: switch count
- K: block count

`constant_sig = f"C_t{tiny}s{small}m{medium}l{large}x{special}"`
- t: tiny
- s: small
- m: medium
- l: large
- x: special

`graph_sig = f"G_n{nodes}e{edges}d{density:.2f}a{avg_degree:.1f}"`
- n: node
- e: edge
- d: density
- a: avg degree

`fingerprint = f"{top_opcodes}|L{loops}B{branches}C{calls}|S{size_bucket}R{reg_count}"`
- L: loop
- B: branch
- C: call
- S: size bucket
- R: register count