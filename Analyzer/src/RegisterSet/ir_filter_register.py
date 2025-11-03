SKIP_REGISTERS = frozenset([
    # CPU flags
    'cf', # carry flag
    'zf', # zero flag
    'sf', # sign flag
    'of', # overflow flag
    'pf', # parity flag
    'af', # auxiliary flag
    'tf', # trap flag
    'if', # interrupt flag  
    'df', # direction flag
    'fl', # flags register (generic)

    # segment registers
    'cs', # code segment
    'ds', # data segment
    'es', # extra segment
    'ss', # stack segment

    # SSE/FPU control
    'mxcsr',  # SSE control/status register

    # FPU condition codes (IDA-generated)
    'c0', # FPU condition code 0
    'c1', # FPU condition code 1 (not seen but should be included)
    'c2', # FPU condition code 2
    'c3', # FPU condition code 3

    # synthetic registers (IDA-generated)
    'fps',# FPU status
    'cc', # condition code

    # memory tracking constructs (IDA synthetic, not registers but worth filtering)
    'GLBLOW',   # global memory low bound tracking
    'GLBHIGH',  # global memory high bound tracking
    'ARGS',     # argument memory region tracking
])

MEMORY_OPS = frozenset([
    'nop',  # m_nop (0x00) - no operation
    'stx',  # m_stx (0x01) - store to memory
    'ldx',  # m_ldx (0x02) - load from memory
    'ldc',  # m_ldc (0x03) - load constant
    'mov',  # m_mov (0x04) - move
])

STACK_OPS = frozenset([
    'push', # m_push (0x3B) - push
    'pop',  # m_pop (0x3C) - pop
])

DATA_OPS = frozenset([
    'xds',  # m_xds (0x08) - extend signed
    'xdu',  # m_xdu (0x09) - extend unsigned
    'low',  # m_low (0x0A) - take low part
    'high', # m_high (0x0B) - take high part
    'f2i',  # m_f2i (0x3F) - float to int
    'f2u',  # m_f2u (0x40) - float to uint
    'i2f',  # m_i2f (0x41) - int to float
    'u2f',  # m_u2f (0x42) - uint to float
    'f2f',  # m_f2f (0x43) - change float precision
])

ARITHMETIC_OPS = frozenset([
    'neg',  # m_neg (0x05) - negate
    'lnot', # m_lnot (0x06) - logical not
    'bnot', # m_bnot (0x07) - bitwise not
    'add',  # m_add (0x0C) - addition
    'sub',  # m_sub (0x0D) - subtraction
    'mul',  # m_mul (0x0E) - multiplication
    'udiv', # m_udiv (0x0F) - unsigned division
    'sdiv', # m_sdiv (0x10) - signed division
    'umod', # m_umod (0x11) - unsigned modulo
    'smod', # m_smod (0x12) - signed modulo
    'or',   # m_or (0x13) - bitwise or
    'and',  # m_and (0x14) - bitwise and
    'xor',  # m_xor (0x15) - bitwise xor
    'shl',  # m_shl (0x16) - shift logical left
    'shr',  # m_shr (0x17) - shift logical right
    'sar',  # m_sar (0x18) - shift arithmetic right
])

FLAG_OPS = frozenset([
    'cfadd',  # m_cfadd (0x19) - calculate carry of add
    'ofadd',  # m_ofadd (0x1A) - calculate overflow of add
    'cfshl',  # m_cfshl (0x1B) - calculate carry of shl
    'cfshr',  # m_cfshr (0x1C) - calculate carry of shr
])

CONDITION_OPS = frozenset([
    'sets',   # m_sets (0x1D) - set if sign (SF=1)
    'seto',   # m_seto (0x1E) - set if overflow
    'setp',   # m_setp (0x1F) - set if parity/unordered
    'setnz',  # m_setnz (0x20) - set if not zero (ZF=0)
    'setz',   # m_setz (0x21) - set if zero (ZF=1)
    'setae',  # m_setae (0x22) - set if above or equal (CF=0)
    'setb',   # m_setb (0x23) - set if below (CF=1)
    'seta',   # m_seta (0x24) - set if above (CF=0 & ZF=0)
    'setbe',  # m_setbe (0x25) - set if below or equal (CF=1 | ZF=1)
    'setg',   # m_setg (0x26) - set if greater (SF=OF & ZF=0)
    'setge',  # m_setge (0x27) - set if greater or equal (SF=OF)
    'setl',   # m_setl (0x28) - set if less (SF!=OF)
    'setle',  # m_setle (0x29) - set if less or equal (SF!=OF | ZF=1)
])

CTRL_OPS = frozenset([
    'jcnd', # m_jcnd (0x2A) - conditional jump
    'jnz',  # m_jnz (0x2B) - jump if not zero (ZF=0)
    'jz',   # m_jz (0x2C) - jump if zero (ZF=1)
    'jae',  # m_jae (0x2D) - jump if above or equal (CF=0)
    'jb',   # m_jb (0x2E) - jump if below (CF=1)
    'ja',   # m_ja (0x2F) - jump if above (CF=0 & ZF=0)
    'jbe',  # m_jbe (0x30) - jump if below or equal (CF=1 | ZF=1)
    'jg',   # m_jg (0x31) - jump if greater (SF=OF & ZF=0)
    'jge',  # m_jge (0x32) - jump if greater or equal (SF=OF)
    'jl',   # m_jl (0x33) - jump if less (SF!=OF)
    'jle',  # m_jle (0x34) - jump if less or equal (SF!=OF | ZF=1)
    'jtbl', # m_jtbl (0x35) - table jump (switch)
    'ijmp', # m_ijmp (0x36) - indirect unconditional jump
    'goto', # m_goto (0x37) - unconditional jump
    'call', # m_call (0x38) - call function
    'icall',# m_icall (0x39) - indirect call
    'ret',  # m_ret (0x3A) - return
])

# floating point
FP_OPS = frozenset([
    'fneg', # m_fneg (0x44) - floating negate
    'fadd', # m_fadd (0x45) - floating add
    'fsub', # m_fsub (0x46) - floating subtract
    'fmul', # m_fmul (0x47) - floating multiply
    'fdiv', # m_fdiv (0x48) - floating divide
])

SPECIAL_OPS = frozenset([
    'und',  # m_und (0x3D) - undefined
    'ext',  # m_ext (0x3E) - external insn (not microcode)
])