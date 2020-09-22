/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      PDP11 module.
 *      Copyright (c) 1995-2006 by Iouri Kharon.
 *                        E-mail: yjh@styx.cabel.net
 *
 *      ALL RIGHTS RESERVED.
 *
 */

#include "pdp.hpp"
//----------------------------------------------------------------------
static const char *const RegNames[] =
{
  "R0","R1","R2","R3","R4","R5","SP","PC",
  "AC0", "AC1", "AC2", "AC3", "AC4", "AC5",
  "cs","ds"
};

//-----------------------------------------------------------------------

static const char *const array_macro[] =
{
  "",
  ".macro .array of,type,cnt,val",
  ".rept  cnt",
  " type  val",
  ".endr",
  ".endm .array",
  NULL
};

static const asm_t macro11 =
{
  /*AS_UNEQU |*/ AS_COLON | AS_2CHRE | AS_NCHRE | ASH_HEXF5 | ASO_OCTF2 | ASD_DECF2 | AS_NCMAS | AS_ONEDUP | ASB_BINF1 | AS_RELSUP,
  UAS_SECT,
  "Macro-11 Assembler",
  0,
  array_macro,  // header
  ".",          // org
  ".END",

  ";",          // comment string
  '\\',         // string delimiter
  '\'',         // char delimiter
  "\\\200",     // special symbols in char and string constants

  ".ascii",     // ascii string directive
  ".byte",      // byte directive
  ".word",      // word directive
  ".long",      // double words
  NULL,         // no qwords
  NULL,         // oword  (16 bytes)
  ".flt2",
  ".flt4",
  NULL,         // no tbytes
  NULL,         // no packreal
  ".array of #hs cnt=#d val=#v",  // #h - header(.byte,.word)
                                  // #d - size of array
                                  // #v - value of array elements
  ".blkb  %s",  // uninited data (reserve space)
  "=",
  NULL,         // seg prefix
  ".",          // a_curip
  NULL,         // func_header
  NULL,         // func_footer
  ".globl",     // public
  ".weak",      // weak
  ".globl",     // extrn
  NULL,         // comm
  NULL,         // get_type_name
  NULL,         // align
  '<', '>',     // lbrace, rbrace
  NULL,         // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "!",          // not
  NULL,         // shl
  NULL,         // shr
  NULL,         // sizeof
};

//--------------------------------------------------------------------------
pdp_ml_t ml = { uint32(BADADDR), 0, 0, 0 };
netnode ovrtrans;

static const char ovrtrans_name[] = "$ pdp-11 overlay translations";

//------------------------------------------------------------------
//  floating point conversion
#include "float.c"

//----------------------------------------------------------------------
static ssize_t idaapi notify(void *, int msgid, va_list va)
{
  int retcode = 1;
  segment_t *sptr;

  switch ( msgid )
  {
    case processor_t::ev_creating_segm:
      sptr = va_arg(va, segment_t *);
      sptr->defsr[rVds-ph.reg_first_sreg] = find_selector(inf.start_cs); //sptr->sel;
      break;

    case processor_t::ev_init:
      ovrtrans.create(ovrtrans_name);   // it makes no harm to create it again
      break;

    case processor_t::ev_newprc:
      break;

    case processor_t::ev_oldfile:
      ml.asect_top = (ushort)ovrtrans.altval(n_asect);
      ml.ovrcallbeg = (ushort)ovrtrans.altval(n_ovrbeg);
      ml.ovrcallend = (ushort)ovrtrans.altval(n_ovrend);
      ml.ovrtbl_base = (uint32)ovrtrans.altval(n_ovrbas);
      break;

    case pdp11_module_t::ev_get_ml_ptr:
      {
        pdp_ml_t **p_ml = va_arg(va, pdp_ml_t **);
        netnode  **p_mn = va_arg(va, netnode **);
        if ( p_ml != NULL && p_mn != NULL )
        {
          *p_ml = &ml;
          *p_mn = &ovrtrans;
          retcode = 0;
        }
      }
      break;

    case processor_t::ev_out_mnem:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_mnem(*ctx);
        return 1;
      }

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        pdp_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        pdp_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        pdp_segstart(*ctx, seg);
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

    case processor_t::ev_out_data:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        bool analyze_only = va_argi(va, bool);
        pdp_data(*ctx, analyze_only);
        return 1;
      }

    case processor_t::ev_realcvt:
      {
        void *m = va_arg(va, void *);
        uint16 *e = va_arg(va, uint16 *);
        uint16 swt = va_argi(va, uint16);
        int code = realcvt(m, e, swt);
        return code == 0 ? 1 : code;
      }

    default:
      retcode = 0;
      break;
  }
  return retcode;
}


//-----------------------------------------------------------------------
static const asm_t *const asms[] = { &macro11, NULL };

#define FAMILY "DEC series:"
static const char *const shnames[] = { "PDP11", NULL };
static const char *const lnames[] = { FAMILY"DEC PDP-11", NULL };

//--------------------------------------------------------------------------
static const uchar retcode_0[] = { 0200, 0000 };
static const uchar retcode_1[] = { 0201, 0000 };
static const uchar retcode_2[] = { 0202, 0000 };
static const uchar retcode_3[] = { 0203, 0000 };
static const uchar retcode_4[] = { 0204, 0000 };
static const uchar retcode_5[] = { 0205, 0000 };
static const uchar retcode_6[] = { 0206, 0000 };
static const uchar retcode_7[] = { 0207, 0000 };
static const uchar retcode_8[] = { 0002, 0000 };
static const uchar retcode_9[] = { 0006, 0000 };

static bytes_t retcodes[] =
{
  { sizeof(retcode_0), retcode_0 },
  { sizeof(retcode_1), retcode_1 },
  { sizeof(retcode_2), retcode_2 },
  { sizeof(retcode_3), retcode_3 },
  { sizeof(retcode_4), retcode_4 },
  { sizeof(retcode_5), retcode_5 },
  { sizeof(retcode_6), retcode_6 },
  { sizeof(retcode_7), retcode_7 },
  { sizeof(retcode_8), retcode_8 },
  { sizeof(retcode_9), retcode_9 },
  { 0, NULL }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_PDP,               // id
                          // flag
    PR_WORD_INS
  | PRN_OCT
  | PR_SEGTRANS,
                          // flag2
    PR2_REALCVT           // the module has 'realcvt' event implementation
  | PR2_IDP_OPTS,         // the module has processor-specific configuration options
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  RegNames,                     // Register names
  qnumber(RegNames),            // Number of registers

  rVcs,rVds,
  0,                            // size of a segment register
  rVcs,rVds,

  NULL,                         // No known code start sequences
  retcodes,

  0,pdp_last,
  Instructions,                 // instruc
  0,    // size of tbyte
  { 4,7,19,0 },

// Icode of return instruction. It is ok to give any of possible return
// instructions
   pdp_return,
};
