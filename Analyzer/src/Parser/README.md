# Parser
## ir_parser.py
### Pattern
example from ir.txt in hello
```
--- IR FOR internal_abi.Kind.String (0x010010A0) ---
106D7C0: using guessed type void __golang __noreturn runtime_panicIndex(_QWORD, _QWORD, _QWORD, _QWORD);
1171700: using guessed type _UNKNOWN *internal_abi_kindNames;
0. 0 ; STKD=0 MINREF=18/END=18 ARGS: OFF=20/MINREF=220/END=220/SHADOW=0
0. 0 ; SAVEDREGS: rbp.8
0. 0 ; 1WAY-BLOCK 0 FAKE OUTBOUNDS: 1 [START=10010A0 END=10010A0] MINREFS: STK=18/ARG=220, MAXBSP: 0
0. 0 ; DEF: (al.1,rbx.8,ds.2,1171700..1171710)
0. 0
1. 0 ; 2WAY-BLOCK 1 INBOUNDS: 0 OUTBOUNDS: 2 4 [START=10010A0 END=10010BE] MINREFS: STK=18/ARG=220, MAXBSP: 18
1. 0 ; USE: al.1,1171708.8
1. 0 jg     $qword_1171708.8{2}, xdu.8(al.1{1}), @4 ; 10010BC u=al.1,1171708.8
1. 0
2. 0 ; 2WAY-BLOCK 2 INBOUNDS: 1 OUTBOUNDS: 3 5 [START=10010BE END=10010C5] MINREFS: STK=18/ARG=220, MAXBSP: 18
2. 0 ; USE: 1171708.8
2. 0 jz     $qword_1171708.8, #0.8, @5 ; 10010C3 u=1171708.8
2. 0
3. 0 ; 1WAY-BLOCK 3 INBOUNDS: 2 OUTBOUNDS: 6 [START=10010C5 END=10010D2] MINREFS: STK=18/ARG=220, MAXBSP: 18
3. 0 ; USE: ds.2,1171700.8,(GLBLOW,100220..1171700,1171708..)
3. 0 ; DEF: rax.8,rbx.8
3. 0 ; DNU: rax.8,rbx.8
3. 0 ldx    ds.2{4}, $"_internal_abi.kindNames".8{5}, rax.8 ; 10010C5 u=ds.2,1171700.8,(GLBLOW,100220..1171700,1171708..) d=rax.8
3. 1 ldx    ds.2{4}, ($"_internal_abi.kindNames".8{5}+#8.8), rbx.8 ; 10010C8 u=ds.2,1171700.8,(GLBLOW,100220..1171700,1171708..) d=rbx.8
3. 2 goto   @6                      ; 10010D1 u=
3. 2
4. 0 ; 1WAY-BLOCK 4 INBOUNDS: 1 OUTBOUNDS: 6 [START=10010D2 END=10010E5] MINREFS: STK=18/ARG=220, MAXBSP: 18
4. 0 ; USE: al.1,ds.2,1171700.8,(GLBLOW,100220..1171700,1171708..)
4. 0 ; DEF: rax.16,rbx.8
4. 0 ; DNU: rax.8,rbx.8
4. 0 mul    #0x10.8, xdu.8(al.1), rdx.8{6} ; 10010D2 u=al.1       d=rdx.8
4. 1 ldx    ds.2{7}, ($"_internal_abi.kindNames".8{9}+rdx.8{6}){8}, rax.8 ; 10010D6 u=rdx.8,ds.2,1171700.8,(GLBLOW,100220..1171700,1171708..) d=rax.8
4. 2 ldx    ds.2{7}, (($"_internal_abi.kindNames".8{9}+rdx.8{6}){8}+#8.8), rbx.8 ; 10010DA u=rdx.8,ds.2,1171700.8,(GLBLOW,100220..1171700,1171708..) d=rbx.8
4. 3 goto   @6                      ; 10010E4 u=
4. 3
5. 0 ; 0WAY-BLOCK 5 INBOUNDS: 2 [START=10010E5 END=10010EF] MINREFS: STK=18/ARG=220, MAXBSP: 18
5. 0 ; USE: rbx.8,1171700.8,(GLBLOW,100220..1171700,1171708..)
5. 0 ; DEF: (cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.16,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,GLBLOW,GLBHIGH)
5. 0 call   $"runtime.panicIndex" <go:_QWORD #0.8,_QWORD rbx.8,_QWORD #0.8,_QWORD $"_internal_abi.kindNames".8{3}>.0 ; 10010EA u=rbx.8,1171700.8,(GLBLOW,100220..1171700,1171708..) d=(cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.16,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,GLBLOW,GLBHIGH)
5. 0
6. 0 ; STOP-BLOCK 6 FAKE INBOUNDS: 3 4 [START=FFFFFFFFFFFFFFFF END=FFFFFFFFFFFFFFFF] MINREFS: STK=18/ARG=220, MAXBSP: 0
6. 0 ; USE: (rax.8,rbx.8)
6. 0
--- END internal_abi.Kind.String ---


--- IR FOR runtime.chanrecv1 (0x0100AD20) ---
100AD20: using guessed type __int64 __golang runtime_chanrecv1();
100AD40: using guessed type __int64 __golang runtime_chanrecv(_QWORD, _QWORD, _QWORD);
0. 0 ; STKD=0 MINREF=20/END=20 ARGS: OFF=28/MINREF=228/END=228/SHADOW=0
0. 0 ; SAVEDREGS: rbp.8
0. 0 ; 1WAY-BLOCK 0 FAKE OUTBOUNDS: 1 [START=100AD20 END=100AD20] MINREFS: STK=20/ARG=228, MAXBSP: 0
0. 0 ; DEF: (rax.8,rbx.8)
0. 0
1. 0 ; 1WAY-BLOCK 1 INBOUNDS: 0 OUTBOUNDS: 2 [START=100AD20 END=100AD32] MINREFS: STK=20/ARG=228, MAXBSP: 20
1. 0 ; USE: rax.8,rbx.8,(GLBLOW,GLBHIGH)
1. 0 ; DEF: rax.8,(cf.1,zf.1,sf.1,of.1,pf.1,rdx.8,rcx.16,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,GLBLOW,GLBHIGH)
1. 0 ; DNU: rax.8
1. 0 mov    call $"runtime.chanrecv"<go:_QWORD rax.8,_QWORD rbx.8,_QWORD #1.8> => __int64 .8, rax.8 ; 100AD2D u=rax.8,rbx.8,(GLBLOW,GLBHIGH) d=rax.8,(cf.1,zf.1,sf.1,of.1,pf.1,rdx.8,rcx.16,rdi.16,r8.8,r9.8,r10.8,r11.8,r12.8,r13.8,fps.2,fl.1,c0.1,c2.1,c3.1,df.1,if.1,xmm0.16,xmm1.16,xmm2.16,xmm3.16,xmm4.16,xmm5.16,xmm6.16,xmm7.16,xmm8.16,xmm9.16,xmm10.16,xmm11.16,xmm12.16,xmm13.16,xmm14.16,GLBLOW,GLBHIGH)
1. 0
2. 0 ; STOP-BLOCK 2 FAKE INBOUNDS: 1 [START=FFFFFFFFFFFFFFFF END=FFFFFFFFFFFFFFFF] MINREFS: STK=20/ARG=228, MAXBSP: 0
2. 0 ; USE: (rax.8)
2. 0
--- END runtime.chanrecv1 ---
```

1. block_pattern

Blocks that have outgoing edges listed.
```
(\d+)\.\s*\d+\s*;\s*.*?-BLOCK\s+(\d+).*?
OUTBOUNDS:\s*([0-9,\s]+).*?\[START=([0-9A-Fa-f]+)\s+END=([0-9A-Fa-f]+)\]

1. 0 ; 2WAY-BLOCK 1 INBOUNDS: 0 OUTBOUNDS: 2 4 [START=10010A0 END=10010BE]
│                 │                        │           │                │
│                 │                        │           │                └─ groups[4] = '10010BE' (END address)
│                 │                        │           └────────────────── groups[3] = '10010A0' (START address)
│                 │                        └────────────────────────────── groups[2] = '2 4' (OUTBOUNDS list)
│                 └─────────────────────────────────────────────────────── groups[1] = '1' (BLOCK ID)
└───────────────────────────────────────────────────────────────────────── groups[0] = '1' (line number)
```


2. simple_block_pattern

Blocks that have no outgoing edges (terminal blocks, INBOUNDS blocks).
```
(\d+)\.\s*\d+\s*;\s*.*?-BLOCK\s+(\d+).*?\[START=([0-9A-Fa-f]+)\s+END=([0-9A-Fa-f]+)\]

5. 0 ; 0WAY-BLOCK 5 INBOUNDS: 2 [START=10010E5 END=10010EF]
│                 │                    │                │
│                 │                    │                └─ groups[3] = '10010EF'
│                 │                    └────────────────── groups[2] = '10010E5'
│                 └─────────────────────────────────────── groups[1] = '5'
└───────────────────────────────────────────────────────── groups[0] = '5'


6. 0 ; STOP-BLOCK 6 FAKE INBOUNDS: 3 4 [START=FFFFFFFFFFFFFFFF END=FFFFFFFFFFFFFFFF]
│                 │                          │                  │
│                 │                          │                  └─ groups[3] = 'FFFFFFFFFFFFFFFF' (END)
│                 │                          └──────────────────── groups[2] = 'FFFFFFFFFFFFFFFF' (START)
│                 └─────────────────────────────────────────────── groups[1] = '6' (BLOCK ID)
│  
└───────────────────────────────────────────────────────────────── groups[0] = '6'
```


3. use_pattern

Registers that are READ/USED in a block.
```
USE:\s*([^;]+)

1. 0 ; USE: al.1,1171708.8
       ¯|¯¯ ¯|¯¯¯¯¯¯¯¯¯¯¯¯¯
        |    └─ group[1] = 'al.1,1171708.8'
        └────── group[0] = 'USE: al.1,1171708.8'


3. 0 ; USE: ds.2,1171700.8,(GLBLOW,100220..1171700,1171708..)
       ¯|¯¯ ¯|¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
        |    └─ group[1] = 'ds.2,1171700.8,(GLBLOW,100220..1171700,1171708..)'
        └────── group[0] = 'USE: ds.2,1171700.8,(GLBLOW,100220..1171700,1171708..)'
```

4. def_pattern

Registers that are WRITTEN/DEFINED in a block.
```
DEF:\s*([^;]+)

0. 0 ; DEF: (al.1,rbx.8,ds.2,1171700..1171710)
       ¯|¯¯ ¯|¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
        │    └─ group[1] = '(al.1,rbx.8,ds.2,1171700..1171710)'
        └────── group[0] = 'DEF: (al.1,rbx.8,ds.2,1171700..1171710)'


3. 0 ; DEF: rax.8,rbx.8
       ¯|¯¯ ¯|¯¯¯¯¯¯¯¯¯
        │    └─ group[1] = 'rax.8,rbx.8'
        └────── group[0] = 'DEF: rax.8,rbx.8'
```

5. call_pattern

Function names being called.
```
call\s+\$"([^"]+)"

5. 0 call   $"runtime.panicIndex" <go:_QWORD #0.8,...>.0
     ¯|¯¯     ¯|¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
      │        └─ group[1] = 'runtime.panicIndex'
      └────────── group[0] = 'call $"runtime.panicIndex"'


1. 0 mov    call $"runtime.chanrecv"<...>
            ¯|¯¯   ¯|¯¯¯¯¯¯¯¯¯¯¯¯¯¯
             │      └─ group[1] = 'runtime.chanrecv'
             └──────── group[0] = 'call $"runtime.chanrecv"'
```

6. instruction_pattern

Instruction details with address.
```
(\d+)\.\s*(\d+)\s+(.*?)\s*;\s*([0-9A-Fa-f]+)

1. 0 jg     $qword_1171708.8{2}, xdu.8(al.1{1}), @4 ; 10010BC u=al.1,1171708.8
│  │ ¯|¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯  │
│  │  │                                               └─ groups[3] = '10010BC'
│  │  └───────────────────────────────────────────────── groups[2] = 'jg     $qword_1171708.8{2}, xdu.8(al.1{1}), @4'
│  └──────────────────────────────────────────────────── groups[1] = '0'
└─────────────────────────────────────────────────────── groups[0] = '1'


4. 0 mul    #0x10.8, xdu.8(al.1), rdx.8{6} ; 10010D2 u=al.1       d=rdx.8
│  │ ¯¯│¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯   │
│  │   │                                      └─ groups[3] = '10010D2'
│  │   └──────────────────────────────────────── groups[2] = 'mul    #0x10.8, xdu.8(al.1), rdx.8{6}'
│  └──────────────────────────────────────────── groups[1] = '0'
└─────────────────────────────────────────────── groups[0] = '4'
```

7. function_header_pattern

Identifies which function the following blocks belong to.
```
---\s*IR\s+FOR\s+(.+?)\s+\(0x[0-9A-Fa-f]+\)\s*---

--- IR FOR internal_abi.Kind.String (0x010010A0) ---
│          ¯│¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯              
│           │                                 
│           └─ group[1] = 'internal_abi.Kind.String'
└───────────── group[0] = '--- IR FOR internal_abi.Kind.String (0x010010A0) ---'


--- IR FOR runtime.chanrecv1 (0x0100AD20) ---
│          ¯│¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
│           │ 
│           └─ group[1] = 'runtime.chanrecv1' (function name)
└───────────── group[0] = '--- IR FOR runtime.chanrecv1 (0x0100AD20) ---'
```

8. bounds_pattern

Parses INBOUNDS/OUTBOUNDS lists to get block IDs.
```
(\d+)

OUTBOUNDS: 2 4
           │ │
           │ └─ Second iteration: groups[0] = '4'
           └─── First  iteration: groups[0] = '2'
Returns: [2, 4]


INBOUNDS: 3 4
          │ │
          │ └─ Second iteration: group[1] = '4'
          └─── First  iteration: group[1] = '3'
Returns: [3, 4]
```

9. reg_pattern

Register names from USE/DEF lists.
```
([a-z]+\d*)\.

USE: al.1,1171708.8
     │
     └─ groups[0] = 'al'

DEF: rax.8,rbx.8
      │     │
      │     └─ Second match: groups[0] = 'rbx'
      └─────── First  match: groups[0] = 'rax'


USE: ds.2,1171700.8,(GLBLOW,100220..1171700,1171708..)
     │
     └─ group[0] = 'ds'
```

10. skip_regs

Filter out CPU flag/status registers that aren't general purpose.
```
frozenset(['cf', 'zf', 'sf', 'of', 'pf', 'fps', 'fl', 'df', 'if'])

DEF: (cf.1,zf.1,sf.1,of.1,pf.1,rax.16,rcx.16,...)
      │    │    │    │    │    │      │
      │    │    │    │    │    │      └─ 'rcx' → KEPT
      │    │    │    │    │    └──────── 'rax' → KEPT
      └────┴────┴────┴────┴────────────── All in skip_regs → FILTERED OUT

Match 1: 'cf.1'
  .group(0) = 'cf.'    (full match including dot)
  .group(1) = 'cf'     (captured part) → in skip_regs → FILTERED OUT

Match 2: 'zf.1'
  .group(0) = 'zf.'
  .group(1) = 'zf'    → in skip_regs → FILTERED OUT

Match 3: 'sf.1'
  .group(0) = 'sf.'
  .group(1) = 'sf'    → in skip_regs → FILTERED OUT

Match 4: 'of.1'
  .group(0) = 'of.'
  .group(1) = 'of'    → in skip_regs → FILTERED OUT

Match 5: 'pf.1'
  .group(0) = 'pf.'
  .group(1) = 'pf'    → in skip_regs → FILTERED OUT

Match 6: 'rax.16'
  .group(0) = 'rax.'
  .group(1) = 'rax'   → NOT in skip_regs → KEPT

Match 7: 'rcx.16'
  .group(0) = 'rcx.'
  .group(1) = 'rcx'   → NOT in skip_regs → KEPT
```

