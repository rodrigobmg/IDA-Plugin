/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-99 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              E-mail: ig@datarescue.com
 *
 *
 */

#include "h8500.hpp"
#include <fpro.h>
#include <diskio.hpp>

#include <ieee.h>

//--------------------------------------------------------------------------
static const char *const register_names[] =
{
  "r0",   "r1",   "r2",  "r3",  "r4",  "r5",  "fp",  "sp",
  "sr",   "ccr",  "?",   "br",  "ep",  "dp",  "cp",  "tp",
};

//--------------------------------------------------------------------------
static const uchar retcode_0[] = { 0x56, 0x70 };  // rte
static const uchar retcode_1[] = { 0x54, 0x70 };  // rts

static const bytes_t retcodes[] =
{
  { sizeof(retcode_0), retcode_0 },
  { sizeof(retcode_1), retcode_1 },
  { 0, NULL }
};

//------------------------------------------------------------------
static void idaapi func_header(outctx_t &ctx, func_t *pfn)
{
  ctx.gen_func_header(pfn);

  if ( ctx.curlabel.empty() )
    return;

  ctx.gen_printf(0, "%s" COLSTR(":", SCOLOR_SYMBOL) " "
                 SCOLOR_ON SCOLOR_AUTOCMT
                 "%s %s"
                 SCOLOR_OFF SCOLOR_AUTOCMT,
                 ctx.curlabel.begin(),
                 ash.cmnt,
                 (pfn->flags & FUNC_FAR) != 0 ? "far" : "near");
  ctx.ctxflags |= CTXF_LABEL_OK;
}

//-----------------------------------------------------------------------
//      GNU ASM
//-----------------------------------------------------------------------
static const asm_t gas =
{
  AS_ASCIIC|ASH_HEXF3|ASD_DECF0|ASB_BINF3|ASO_OCTF1|AS_COLON|AS_N2CHR|AS_NCMAS|AS_ONEDUP,
  0,
  "GNU assembler",
  0,
  NULL,         // header lines
  ".org",       // org
  NULL,         // end

  "!",          // comment string
  '"',          // string delimiter
  '"',          // char delimiter
  "\"",         // special symbols in char and string constants

  ".ascii",     // ascii string directive
  ".byte",      // byte directive
  ".word",      // word directive
  ".long",      // double words
  NULL,         // qwords
  NULL,         // oword  (16 bytes)
  ".float",     // float  (4 bytes)
  NULL,         // double (8 bytes)
  NULL,         // tbyte  (10/12 bytes)
  NULL,         // packed decimal real
  NULL,         // arrays (#h,#d,#v,#s(...)
  ".space %s",  // uninited arrays
  "=",          // equ
  NULL,         // 'seg' prefix (example: push seg seg001)
  NULL,         // current IP (instruction pointer)
  func_header,  // func_header
  NULL,         // func_footer
  ".globl",     // "public" name keyword
  NULL,         // "weak"   name keyword
  ".extern",    // "extrn"  name keyword
                // .extern directive requires an explicit object size
  ".comm",      // "comm" (communal variable)
  NULL,         // get_type_name
  ".align",     // "align" keyword
  '(', ')',     // lbrace, rbrace
  "%",          // mod
  "&",          // and
  "|",          // or
  "^",          // xor
  "~",          // not
  "<<",         // shl
  ">>",         // shr
  NULL,         // sizeof
  AS2_COLONSUF, // flag2
  NULL,         // cmnt2
  NULL,         // low8
  NULL,         // high8
  NULL,         // low16
  NULL,         // high16
  "#include \"%s\"",  // a_include_fmt
};

static const asm_t *const asms[] = { &gas, NULL };
static ioports_t ports;

//--------------------------------------------------------------------------
static void load_symbols(const char *file)
{
  ports.clear();

  // KLUDGE: read_ioports() will complain if the file is
  // not present, but we don't want that.
  char cfgpath[QMAXPATH];
  const char *rfile = getsysfile(cfgpath, sizeof(cfgpath), file, CFG_SUBDIR);
  if ( rfile != NULL )
    read_ioports(&ports, NULL, file);
}

//--------------------------------------------------------------------------
const char *find_sym(int address)
{
  const ioport_t *port = find_ioport(ports, address);
  return port != NULL ? port->name.c_str() : NULL;
}


//------------------------------------------------------------------
const char *idaapi set_idp_options(const char *keyword,int value_type,const void *value)
{
  static const char form[] =
    "HELP\n"
    "H8/500 specific analyzer options\n"
    "\n"
    "Disassemble mixed size instructions\n"
    "\n"
    "        According to the documentation, instructions like\n"
    "\n"
    "        cmp:g.b #1:16, @0x222:16\n"
    "\n"
    "        are not allowed. The correct instruction is:\n"
    "\n"
    "        cmp:g.b #1:8, @0x222:16\n"
    "\n"
    "        The size of the first operand should agree with the size\n"
    "        of the instruction. (exception mov:g)\n"
    "\n"
    "ENDHELP\n"
    "H8/500 specific analyzer options\n"
    "\n"
    // m
    " <Disassemble ~m~ixed size instructions:C>>\n"
    "\n"
    "\n";

  if ( keyword == NULL )
  {
    ask_form(form, &idpflags);
    return IDPOPT_OK;
  }
  if ( strcmp(keyword,"H8500_MIXED_SIZE") == 0 )
  {
    if ( value_type != IDPOPT_BIT )
      return IDPOPT_BADTYPE;
    setflag(idpflags, AFIDP_MIXSIZE, *(int*)value != 0);
    return IDPOPT_OK;
  }
  return IDPOPT_BADKEY;
}

//-----------------------------------------------------------------------
#define FAMILY "Hitachi H8/500:"
static const char *const shnames[] = { "h8500", NULL };
static const char *const lnames[] =
{
  FAMILY"Hitachi H8/500",
  NULL
};

//-----------------------------------------------------------------------
// temporary solution for v4.7
static ea_t idaapi h8_extract_address(ea_t screen_ea, const char *string, size_t x)
{
  size_t len = strlen(string);
  if ( len == 0 || x > len )
    return BADADDR;
  if ( x == len )
    x--;
  const char *ptr = string + x;
  while ( ptr > string && qisxdigit(ptr[-1]) )
    ptr--;
  const char *start = ptr;
  while ( qisxdigit(ptr[0]) )
    ptr++;
  len = ptr - start;
  char buf[MAXSTR];
  memcpy(buf, start, len);
  buf[len] = '\0';
  ea_t ea = BADADDR;
  str2ea(&ea, buf, screen_ea);
  return ea;
}

//------------------------------------------------------------------------
static bool idaapi can_have_type(const op_t &x)      // returns 1 - operand can have
{
  switch ( x.type )
  {
    case o_void:
    case o_reg:
    case o_reglist:
      return false;
    case o_phrase:
      return x.phtype == ph_normal;
  }
  return true;
}

//--------------------------------------------------------------------------
netnode helper;
ushort idpflags = AFIDP_MIXSIZE;

//--------------------------------------------------------------------------
static ssize_t idaapi idb_callback(void *, int code, va_list /*va*/)
{
  switch ( code )
  {
    case idb_event::closebase:
    case idb_event::savebase:
      helper.altset(-1, idpflags - 1);
      break;
  }
  return 0;
}

//--------------------------------------------------------------------------
static ssize_t idaapi notify(void *, int msgid, va_list va)
{
  int code = 0;
  switch ( msgid )
  {
    case processor_t::ev_init:
//      __emit__(0xCC);   // debugger trap
      hook_to_notification_point(HT_IDB, idb_callback);
      helper.create("$ h8/500");
      inf.set_be(true);
      break;

    case processor_t::ev_term:
      ports.clear();
      unhook_from_notification_point(HT_IDB, idb_callback);
      break;

    case processor_t::ev_oldfile:   // old file loaded
      idpflags = ushort(helper.altval(-1) + 1);
      // no break
    case processor_t::ev_newfile:   // new file loaded
      load_symbols("h8500.cfg");
      inf.set_be(true);
      break;

    case processor_t::ev_creating_segm:    // new segment
      {
        segment_t *sptr = va_arg(va, segment_t *);
        sptr->defsr[BR-ph.reg_first_sreg] = 0;
        sptr->defsr[DP-ph.reg_first_sreg] = 0;
      }
      break;

    case processor_t::ev_is_jump_func:
      {
        const func_t *pfn = va_arg(va, const func_t *);
        ea_t *jump_target = va_arg(va, ea_t *);
        return is_jump_func(pfn, jump_target);
      }

    case processor_t::ev_is_sane_insn:
      {
        const insn_t *insn = va_arg(va, insn_t *);
        int no_crefs = va_arg(va, int);
        return is_sane_insn(*insn, no_crefs) == 1 ? 1 : -1;
      }

    case processor_t::ev_may_be_func:
      {
        const insn_t *insn = va_arg(va, insn_t *);
        return may_be_func(*insn);
      }

    case processor_t::ev_out_mnem:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        out_mnem(*ctx);
        return 1;
      }

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        h8500_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        h8500_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        h8500_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_segend:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        h8500_segend(*ctx, seg);
        return 1;
      }

    case processor_t::ev_out_assumes:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        h8500_assume(*ctx);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return h8500_ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return h8500_emu(*insn) ? 1 : -1;
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

    case processor_t::ev_can_have_type:
      {
        const op_t *op = va_arg(va, const op_t *);
        return can_have_type(*op) ? 1 : -1;
      }

    case processor_t::ev_realcvt:
      {
        void *m = va_arg(va, void *);
        uint16 *e = va_arg(va, uint16 *);
        uint16 swt = va_argi(va, uint16);
        int code1 = ieee_realcvt(m, e, swt);
        return code1 == 0 ? 1 : code1;
      }

    case processor_t::ev_extract_address:
      {
        ea_t *out_ea = va_arg(va, ea_t *);
        ea_t screen_ea = va_arg(va, ea_t);
        const char *str = va_arg(va, const char *);
        size_t pos = va_arg(va, size_t);
        ea_t ea = h8_extract_address(screen_ea, str, pos);
        if ( ea == BADADDR )
          return -1;
        if ( ea == (BADADDR-1) )
          return 0;
        *out_ea = ea;
        return 1;
      }

    case processor_t::ev_is_sp_based:
      {
        int *mode = va_arg(va, int *);
        const insn_t *insn = va_arg(va, const insn_t *);
        const op_t *op = va_arg(va, const op_t *);
        *mode = is_sp_based(*insn, *op);
        return 1;
      }

    case processor_t::ev_create_func_frame:
      {
        func_t *pfn = va_arg(va, func_t *);
        create_func_frame(pfn);
        return 1;
      }

    case processor_t::ev_get_frame_retsize:
      {
        int *frsize = va_arg(va, int *);
        const func_t *pfn = va_arg(va, const func_t *);
        *frsize = h8500_get_frame_retsize(pfn);
        return 1;
      }

    case processor_t::ev_set_idp_options:
      {
        const char *keyword = va_arg(va, const char *);
        int value_type = va_arg(va, int);
        const char *value = va_arg(va, const char *);
        const char *ret = set_idp_options(keyword, value_type, value);
        if ( ret == IDPOPT_OK )
          return 1;
        const char **errmsg = va_arg(va, const char **);
        if ( errmsg != NULL )
          *errmsg = ret;
        return -1;
      }

    case processor_t::ev_is_align_insn:
      {
        ea_t ea = va_arg(va, ea_t);
        return is_align_insn(ea);
      }

    default:
      break;
  }
  return code;
}

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_H8500,             // id
                          // flag
    PRN_HEX
  | PR_SEGS
  | PR_SGROTHER,
                          // flag2
    PR2_REALCVT           // the module has 'realcvt' event implementation
  | PR2_IDP_OPTS,         // the module has processor-specific configuration options
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte for other segments

  shnames,
  lnames,

  asms,

  notify,

  register_names,       // Register names
  qnumber(register_names), // Number of registers

  BR,                   // first
  TP,                   // last
  1,                    // size of a segment register
  CP, DP,

  NULL,                 // No known code start sequences
  retcodes,

  H8500_null,
  H8500_last,
  Instructions,         // instruc
  0,                    // int tbyte_size;  -- doesn't exist
  { 0, 7, 15, 0 },      // char real_width[4];
                        // number of symbols after decimal point
                        // 2byte float (0-does not exist)
                        // normal float
                        // normal double
                        // long double
  H8500_rts,            // Icode of return instruction. It is ok to give any of possible return instructions
};
