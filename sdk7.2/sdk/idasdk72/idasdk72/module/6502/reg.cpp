/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "m65.hpp"

//--------------------------------------------------------------------------
static const char *const RegNames[] =
{
  "A", "X", "Y", "cs", "ds"
};

//----------------------------------------------------------------------
int is_cmos = 0;

static ssize_t idaapi notify(void *, int msgid, va_list va)
{
  switch ( msgid )
  {
    case processor_t::ev_newprc:
      is_cmos = va_arg(va, int);
      break;

    case processor_t::ev_creating_segm:
      {                  // default DS is equal to CS
        segment_t *sptr = va_arg(va, segment_t *);
        sptr->defsr[rVds-ph.reg_first_sreg] = sptr->sel;
      }
      break;

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return emu(*insn) ? 1 : -1;
      }

    case processor_t::ev_out_insn:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_insn(*ctx);
        return 1;
      }

    case processor_t::ev_out_operand:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const op_t *op = va_arg(va, const op_t *);
        return out_opnd(*ctx, *op) ? 1 : -1;
      }

    default:
      break;
  }
  return 0;
}

//-----------------------------------------------------------------------
//      PseudoSam
//-----------------------------------------------------------------------
static const char *const ps_headers[] =
{
  ".code",
  NULL
};

static const asm_t pseudosam =
{
  AS_COLON | ASH_HEXF1 | AS_N2CHR | AS_NOXRF,
  UAS_SELSG,
  "PseudoSam by PseudoCode",
  0,
  ps_headers,
  ".org",
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".db",        // ascii string directive
  ".db",        // byte directive
  ".dw",        // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".rs %s",     // uninited arrays
  ".equ",       // equ
  NULL,         // seg prefix
  NULL,         // curip
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
  NULL,    // mod
  NULL,    // and
  NULL,    // or
  NULL,    // xor
  NULL,    // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
};


//-----------------------------------------------------------------------
//      SVENSON ELECTRONICS 6502/65C02 ASSEMBLER - V.1.0 - MAY, 1988
//-----------------------------------------------------------------------
static const asm_t svasm =
{
  AS_COLON | ASH_HEXF4,
  UAS_NOSEG,
  "SVENSON ELECTRONICS 6502/65C02 ASSEMBLER - V.1.0 - MAY, 1988",
  0,
  NULL,         // headers
  "* = ",
  ".END",

  ";",          // comment string
  '\'',         // string delimiter
  '\'',         // char delimiter
  "\\'",        // special symbols in char and string constants

  ".BYTE",      // ascii string directive
  ".BYTE",      // byte directive
  ".WORD",      // word directive
};

//-----------------------------------------------------------------------
//      TASM assembler definiton
//-----------------------------------------------------------------------
static const asm_t tasm =
{
  AS_COLON | AS_N2CHR | AS_1TEXT,
  UAS_NOENS | UAS_NOSEG,
  "Table Driven Assembler (TASM) by Speech Technology Inc.",
  0,
  NULL,         // headers,
  ".org",
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".text",      // ascii string directive
  ".db",        // byte directive
  ".dw",        // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".block %s",  // uninited arrays
  ".equ",
  NULL,         // seg prefix
  NULL,         // curip
  NULL,         // func_header
  NULL,         // func_footer
  NULL,         // public
  NULL,         // weak
  NULL,         // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '(', ')',     // lbrace, rbrace
  NULL,     // mod
  "and",    // and
  "or",     // or
  NULL,    // xor
  "not",    // not
  NULL,    // shl
  NULL,    // shr
  NULL,    // sizeof
};


//-----------------------------------------------------------------------
//      Avocet assembler definiton
//-----------------------------------------------------------------------
static const asm_t avocet =
{
  AS_COLON | AS_N2CHR | AS_1TEXT,
  UAS_NOENS | UAS_NOSEG,
  "Avocet Systems 2500AD 6502 Assembler",
  0,
  NULL,         // headers,
  ".org",
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".fcc",       // ascii string directive
  ".db",        // byte directive
  ".dw",        // word directive
  NULL,         // dword  (4 bytes)
  NULL,         // qword  (8 bytes)
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".ds %s",     // uninited arrays
};

static const asm_t *const asms[] = { &svasm, &tasm, &pseudosam, &avocet, NULL };
//-----------------------------------------------------------------------
#define FAMILY "MOS Technology 65xx series:"
static const char *const shnames[] = { "M6502", "M65C02", NULL };
static const char *const lnames[] = { FAMILY"MOS Technology 6502", "MOS Technology 65C02", NULL };

//--------------------------------------------------------------------------
static const uchar retcode_1[] = { 0x60 };
static const uchar retcode_2[] = { 0x40 };

static const bytes_t retcodes[] =
{
  { sizeof(retcode_1), retcode_1 },
  { sizeof(retcode_2), retcode_2 },
  { 0, NULL }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_6502,              // id
                          // flag
    PR_SEGS
  | PR_SEGTRANS,
                          // flag2
  0,
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  RegNames,             // Register names
  qnumber(RegNames),    // Number of registers

  rVcs,                 // first
  rVds,                 // last
  0,                    // size of a segment register
  rVcs,rVds,

  NULL,                 // No known code start sequences
  retcodes,

  0,M65_last,
  Instructions,         // instruc
};
