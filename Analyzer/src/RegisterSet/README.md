# Register Set
## ir_filter_register.py
### hexrays
- [hexrays.hpp code](https://cpp.docs.hex-rays.com/hexrays_8hpp_source.html)
- [hexrays.hpp documentation](https://cpp.docs.hex-rays.com/hexrays_8hpp.html)
- [Hex-Rays Microcode API vs. Obfuscating Compiler](https://hex-rays.com/blog/hex-rays-microcode-api-vs-obfuscating-compiler)

```
//-------------------------------------------------------------------------
// List of microinstruction opcodes.
// The order of setX and jX insns is important, it is used in the code.
 
// Instructions marked with *F may have the FPINSN bit set and operate on fp values
// Instructions marked with +F must have the FPINSN bit set. They always operate on fp values
// Other instructions do not operate on fp values.
 
enum mcode_t
{
  m_nop    = 0x00, // nop                       // no operation
  m_stx    = 0x01, // stx  l,    {r=sel, d=off} // store register to memory     *F
  m_ldx    = 0x02, // ldx  {l=sel,r=off}, d     // load register from memory    *F
  m_ldc    = 0x03, // ldc  l=const,     d       // load constant
  m_mov    = 0x04, // mov  l,           d       // move                         *F
  m_neg    = 0x05, // neg  l,           d       // negate
  m_lnot   = 0x06, // lnot l,           d       // logical not
  m_bnot   = 0x07, // bnot l,           d       // bitwise not
  m_xds    = 0x08, // xds  l,           d       // extend (signed)
  m_xdu    = 0x09, // xdu  l,           d       // extend (unsigned)
  m_low    = 0x0A, // low  l,           d       // take low part
  m_high   = 0x0B, // high l,           d       // take high part
  m_add    = 0x0C, // add  l,   r,      d       // l + r -> dst
  m_sub    = 0x0D, // sub  l,   r,      d       // l - r -> dst
  m_mul    = 0x0E, // mul  l,   r,      d       // l * r -> dst
  m_udiv   = 0x0F, // udiv l,   r,      d       // l / r -> dst
  m_sdiv   = 0x10, // sdiv l,   r,      d       // l / r -> dst
  m_umod   = 0x11, // umod l,   r,      d       // l % r -> dst
  m_smod   = 0x12, // smod l,   r,      d       // l % r -> dst
  m_or     = 0x13, // or   l,   r,      d       // bitwise or
  m_and    = 0x14, // and  l,   r,      d       // bitwise and
  m_xor    = 0x15, // xor  l,   r,      d       // bitwise xor
  m_shl    = 0x16, // shl  l,   r,      d       // shift logical left
  m_shr    = 0x17, // shr  l,   r,      d       // shift logical right
  m_sar    = 0x18, // sar  l,   r,      d       // shift arithmetic right
  m_cfadd  = 0x19, // cfadd l,  r,    d=carry   // calculate carry    bit of (l+r)
  m_ofadd  = 0x1A, // ofadd l,  r,    d=overf   // calculate overflow bit of (l+r)
  m_cfshl  = 0x1B, // cfshl l,  r,    d=carry   // calculate carry    bit of (l<<r)
  m_cfshr  = 0x1C, // cfshr l,  r,    d=carry   // calculate carry    bit of (l>>r)
  m_sets   = 0x1D, // sets  l,          d=byte  SF=1          Sign
  m_seto   = 0x1E, // seto  l,  r,      d=byte  OF=1          Overflow of (l-r)
  m_setp   = 0x1F, // setp  l,  r,      d=byte  PF=1          Unordered/Parity        *F
  m_setnz  = 0x20, // setnz l,  r,      d=byte  ZF=0          Not Equal               *F
  m_setz   = 0x21, // setz  l,  r,      d=byte  ZF=1          Equal                   *F
  m_setae  = 0x22, // setae l,  r,      d=byte  CF=0          Unsigned Above or Equal *F
  m_setb   = 0x23, // setb  l,  r,      d=byte  CF=1          Unsigned Below          *F
  m_seta   = 0x24, // seta  l,  r,      d=byte  CF=0 & ZF=0   Unsigned Above          *F
  m_setbe  = 0x25, // setbe l,  r,      d=byte  CF=1 | ZF=1   Unsigned Below or Equal *F
  m_setg   = 0x26, // setg  l,  r,      d=byte  SF=OF & ZF=0  Signed Greater
  m_setge  = 0x27, // setge l,  r,      d=byte  SF=OF         Signed Greater or Equal
  m_setl   = 0x28, // setl  l,  r,      d=byte  SF!=OF        Signed Less
  m_setle  = 0x29, // setle l,  r,      d=byte  SF!=OF | ZF=1 Signed Less or Equal
  m_jcnd   = 0x2A, // jcnd   l,         d       // d is mop_v or mop_b
  m_jnz    = 0x2B, // jnz    l, r,      d       // ZF=0          Not Equal               *F
  m_jz     = 0x2C, // jz     l, r,      d       // ZF=1          Equal                   *F
  m_jae    = 0x2D, // jae    l, r,      d       // CF=0          Unsigned Above or Equal *F
  m_jb     = 0x2E, // jb     l, r,      d       // CF=1          Unsigned Below          *F
  m_ja     = 0x2F, // ja     l, r,      d       // CF=0 & ZF=0   Unsigned Above          *F
  m_jbe    = 0x30, // jbe    l, r,      d       // CF=1 | ZF=1   Unsigned Below or Equal *F
  m_jg     = 0x31, // jg     l, r,      d       // SF=OF & ZF=0  Signed Greater
  m_jge    = 0x32, // jge    l, r,      d       // SF=OF         Signed Greater or Equal
  m_jl     = 0x33, // jl     l, r,      d       // SF!=OF        Signed Less
  m_jle    = 0x34, // jle    l, r,      d       // SF!=OF | ZF=1 Signed Less or Equal
  m_jtbl   = 0x35, // jtbl   l, r=mcases        // Table jump
  m_ijmp   = 0x36, // ijmp       {r=sel, d=off} // indirect unconditional jump
  m_goto   = 0x37, // goto   l                  // l is mop_v or mop_b
  m_call   = 0x38, // call   l          d       // l is mop_v or mop_b or mop_h
  m_icall  = 0x39, // icall  {l=sel, r=off} d   // indirect call
  m_ret    = 0x3A, // ret
  m_push   = 0x3B, // push   l
  m_pop    = 0x3C, // pop               d
  m_und    = 0x3D, // und               d       // undefine
  m_ext    = 0x3E, // ext  in1, in2,  out1      // external insn, not microcode *F
  m_f2i    = 0x3F, // f2i    l,    d       int(l) => d; convert fp -> integer   +F
  m_f2u    = 0x40, // f2u    l,    d       uint(l)=> d; convert fp -> uinteger  +F
  m_i2f    = 0x41, // i2f    l,    d       fp(l)  => d; convert integer -> fp   +F
  m_u2f    = 0x42, // i2f    l,    d       fp(l)  => d; convert uinteger -> fp  +F
  m_f2f    = 0x43, // f2f    l,    d       l      => d; change fp precision     +F
  m_fneg   = 0x44, // fneg   l,    d       -l     => d; change sign             +F
  m_fadd   = 0x45, // fadd   l, r, d       l + r  => d; add                     +F
  m_fsub   = 0x46, // fsub   l, r, d       l - r  => d; subtract                +F
  m_fmul   = 0x47, // fmul   l, r, d       l * r  => d; multiply                +F
  m_fdiv   = 0x48, // fdiv   l, r, d       l / r  => d; divide                  +F
#define m_max 0x49 // first unused opcode
};
```

### CPU FPU Registers
- [CPU Registers x86-64](https://wiki.osdev.org/CPU_Registers_x86-64)

```
Segment Registers
| Moniker | Description                                |
|---------|--------------------------------------------|
| CS      | Code Segment                               |
| DS      | Data Segment                               |
| SS      | Stack Segment                              |
| ES      | Extra Segment (used for string operations) |

Flags Register (RFLAGS) Bits
| Bit Number | Label | Description           |
|------------|-------|-----------------------|
| 0          | CF    | Carry Flag            |
| 2          | PF    | Parity Flag           |
| 4          | AF    | Auxiliary Carry Flag  |
| 6          | ZF    | Zero Flag             |
| 7          | SF    | Sign Flag             |
| 8          | TF    | Trap Flag             |
| 9          | IF    | Interrupt Enable Flag |
| 10         | DF    | Direction Flag        |
| 11         | OF    | Overflow Flag         |
```

- [microcomputers and memories](https://bitsavers.trailing-edge.com/www.computer.museum.uq.edu.au/pdf/Microcomputers%20and%20Memories%201982%20(Preliminary).pdf)

```
Page 118 # FLOATING POINT STATUS REGISTER (FPS)
This register provides mode and interrupt control for the floating point
unit and conditions resulting from the execution of the previous instruction. 

Page 76 # SPECIAL SYMBOLS
CC: Condition Code
```
