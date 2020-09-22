/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 */

#include "tms.hpp"

//--------------------------------------------------------------------------
static const char *const RegNames[] =
{
  "acc","p","bmar",
  "ar0","ar1","ar2","ar3","ar4","ar5","ar6","ar7",
  "cs","ds","dp"
};

//--------------------------------------------------------------------------
static predefined_t iregs[] =
{
  { 0x00, "Reserved_0",   NULL },
  { 0x01, "Reserved_1",   NULL },
  { 0x02, "Reserved_2",   NULL },
  { 0x03, "Reserved_3",   NULL },
  { 0x04, "imr",          "Interrupt mask register" },
  { 0x05, "greg",         "Global memory allocation register" },
  { 0x06, "ifr",          "Interrupt flag register" },
  { 0x07, "pmst",         "Processor mode status register" },
  { 0x08, "rptc",         "Repeat counter register" },
  { 0x09, "brcr",         "Block repeat counter register" },
  { 0x0A, "pasr",         "Block repeat program address start register" },
  { 0x0B, "paer",         "Block repeat program address end register" },
  { 0x0C, "treg0",        "Temp reg - multiplicand" },
  { 0x0D, "treg1",        "Temp reg - dynamic shift count (5 bits)" },
  { 0x0E, "treg2",        "Temp reg - bit pointer in dynamic bit test (4 bits)" },
  { 0x0F, "dbmr",         "Dynamic bit manipulation register" },
  { 0x10, "ar0",          NULL },
  { 0x11, "ar1",          NULL },
  { 0x12, "ar2",          NULL },
  { 0x13, "ar3",          NULL },
  { 0x14, "ar4",          NULL },
  { 0x15, "ar5",          NULL },
  { 0x16, "ar6",          NULL },
  { 0x17, "ar7",          NULL },
  { 0x18, "indx",         "Index register" },
  { 0x19, "arcr",         "Auxiliary compare register" },
  { 0x1A, "cbsr1",        "Circular buffer 1 start" },
  { 0x1B, "cber1",        "Circular buffer 1 end" },
  { 0x1C, "cbsr2",        "Circular buffer 2 start" },
  { 0x1D, "cber2",        "Circular buffer 2 end" },
  { 0x1E, "cbcr",         "Circular buffer control register" },
  { 0x1F, "bmar",         "Block move address register" },
  { 0x20, "drr",          "Data receive register" },
  { 0x21, "dxr",          "Data transmit register" },
  { 0x22, "spc",          "Serial port control register" },
  { 0x23, "Reserved_23",  NULL },
  { 0x24, "tim",          "Timer register" },
  { 0x25, "prd",          "Period register" },
  { 0x26, "tcr",          "Timer control register" },
  { 0x27, "Reserved_27",  NULL },
  { 0x28, "pdwsr",        "Program/Data S/W Wait-State register" },
  { 0x29, "iowsr",        "I/O Port S/W Wait-State register" },
  { 0x2A, "cwsr",         "Control S/W Wait-State register" },
  { 0x2B, "Reserved_2b",  NULL },
  { 0x2C, "Reserved_2c",  NULL },
  { 0x2D, "Reserved_2d",  NULL },
  { 0x2E, "Reserved_2e",  NULL },
  { 0x2F, "Reserved_2f",  NULL },
  { 0x30, "trcv",         "TDM Data receive register" },
  { 0x31, "tdxr",         "TDM Data transmit register" },
  { 0x32, "tspc",         "TDM Serial port control register" },
  { 0x33, "tcsr",         "TDM channel select register" },
  { 0x34, "trta",         "TDM Receive/Transmit address register" },
  { 0x35, "trad",         "TDM Received address register" },
  { 0x00, NULL,           NULL }
};

static predefined_t c2_iregs[] =
{
  { 0x00, "drr",          "Data receive register" },
  { 0x01, "dxr",          "Data transmit register" },
  { 0x02, "tim",          "Timer register" },
  { 0x03, "prd",          "Period register" },
  { 0x04, "imr",          "Interrupt mask register" },
  { 0x05, "greg",         "Global memory allocation register" },
  { 0x00, NULL,           NULL }
};

//----------------------------------------------------------------------
static ssize_t idaapi notify(void *, int msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_newfile:
      {
        inf.set_wide_high_byte_first(true);
        segment_t *sptr = get_first_seg();
        ea_t codeseg;
        if ( sptr != NULL )
        {
          codeseg = sptr->start_ea;
          if ( codeseg-get_segm_base(sptr) == 0 )
          {
            inf.start_ea = sptr->start_ea;
            inf.start_ip = 0;
          }
        }
        else
        {
          codeseg = BADADDR;
        }
        set_segm_class(sptr, "CODE");
        set_segm_name(sptr,"cseg");
        sel_t sel;
        ea_t data_start;
        segment_t *s1 = get_next_seg(codeseg);
        if ( s1 == NULL )
        {
          segment_t s;
          uint32 size = 64 * 1024L;
          s.start_ea = free_chunk(0,size,0xF);
          s.end_ea = s.start_ea + size;
          s.sel   = ushort(s.start_ea >> 4);
          s.align = saRelByte;
          s.comb  = scPub;
          add_segm_ex(&s, "dseg", NULL, ADDSEG_NOSREG);
          sel = s.sel;
          data_start = s.start_ea;
        }
        else
        {
          sel = s1->sel;
          data_start = s1->start_ea;
        }
        set_default_sreg_value(getseg(codeseg), rVds, sel);
        split_sreg_range(inf.start_ea, rDP, 0, SR_auto);
        inf.nametype = NM_NAM_OFF;


        predefined_t *ptr = isC2() ? c2_iregs : iregs;
        for ( ; ptr->name != NULL; ptr++ )
        {
          ea_t ea = data_start + ptr->addr;
          create_byte(ea,1);
          set_name(ea, ptr->name);
          if ( ptr->cmt != NULL )
            set_cmt(ea, ptr->cmt, true);
        }
      }
      break;

    case processor_t::ev_newprc:
      nprc = va_arg(va, int);
      // bool keep_cfg = va_argi(va, bool);
      break;

    case processor_t::ev_oldfile:
      inf.set_wide_high_byte_first(true);     // to be able to work with old bases
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

    case processor_t::ev_out_assumes:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        tms_assumes(*ctx);
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
  return code;
}

//-----------------------------------------------------------------------
//              DSP Fixed Point COFF Assembler Version 6.20
//              Copyright (c) 1987-1991  Texas Instruments Incorporated
//-----------------------------------------------------------------------
static const char *const dspasm_header[] =
{
  ".mmregs",
  NULL
};

static const asm_t dspasm =
{
  AS_COLON | ASH_HEXF0,
  0,
  "DSP Fixed Point COFF Assembler Version 6.20",
  0,
  dspasm_header,        // header lines
  NULL,         // org
  ".end",

  ";",          // comment string
  '"',          // string delimiter
  '\'',         // char delimiter
  "\\\"'",      // special symbols in char and string constants

  ".string",    // ascii string directive
  ".word",      // byte directive
  ".long",      // word directive
  NULL,         // double words
  NULL,         // no qwords
  NULL,         // oword  (16 bytes)
  NULL,         // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".space 16*%s",// uninited arrays
  ".set",       // equ
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


static const asm_t *const asms[] = { &dspasm, NULL };
//-----------------------------------------------------------------------
#define FAMILY "TMS320C5x series:"
static const char *const shnames[] = { "TMS320C5", "TMS320C2", NULL };
static const char *const lnames[] =
{
  FAMILY"Texas Instruments TMS320C5x",
  "Texas Instruments TMS320C2x",
  NULL
};

int nprc;       // processor number
//--------------------------------------------------------------------------
static const uchar retcode_1[] = { 0x00, 0xEF };
static const uchar retcode_2[] = { 0x00, 0xFF };
static const uchar retcode_3[] = { 0x3A, 0xBE };
static const uchar retcode_4[] = { 0x38, 0xBE };

static bytes_t retcodes[] =
{
  { sizeof(retcode_1), retcode_1 },
  { sizeof(retcode_2), retcode_2 },
  { sizeof(retcode_3), retcode_3 },
  { sizeof(retcode_4), retcode_4 },
  { 0, NULL }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_TMS,               // id
                          // flag
    PR_SEGS
  | PR_RNAMESOK           // can use register names for byte names
  | PR_SEGTRANS,
                          // flag2
  0,
  16,                     // 8 bits in a byte for code segments
  16,                     // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  RegNames,                     // Register names
  qnumber(RegNames),            // Number of registers

  rVcs,                         // first
  rDP,                          // last
  2,                            // size of a segment register
  rVcs,rVds,

  NULL,                         // No known code start sequences
  retcodes,

  0,TMS_last,
  Instructions,                 // instruc
};
