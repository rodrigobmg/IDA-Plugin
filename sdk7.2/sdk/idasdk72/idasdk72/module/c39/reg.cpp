/*
 *      Rockwell C39 processor module for IDA.
 *      Copyright (c) 2000-2006 Konstantin Norvatoff, <konnor@bk.ru>
 *      Freeware.
 */

#include "c39.hpp"
#include <diskio.hpp>
#include <segregs.hpp>

//--------------------------------------------------------------------------
// ᯨ᮪ ॣ���஢
static const char *const RegNames[] =
{
  // �㫥���
  "",
  // ����� ॣ�����
  "A","X","Y",
  // �ᥢ��-ᥣ����
  "cs","ds"
};

static netnode helper;
qstring device;
static ioports_t ports;

#include "../iocommon.cpp"

//----------------------------------------------------------------------
static ssize_t idaapi notify(void *, int msgid, va_list va)
{
  switch ( msgid )
  {
    case processor_t::ev_init:
      inf.set_gen_lzero(true);
      helper.create("$ C39");
      break;

    case processor_t::ev_term:
      ports.clear();
      break;

    case processor_t::ev_newfile:
      //�뢮��� ���. ���� �����஢, � �������� ����� �㦭�, ���뢠�� ��� ��࠭���
      //������ ���ଠ�� �� cfg. �� ��⠭�� ���ଠ樨 ������뢠�� ����� � ॣ����
      {
        char cfgfile[QMAXFILE];
        get_cfg_filename(cfgfile, sizeof(cfgfile));
        if ( choose_ioport_device(&device, cfgfile, parse_area_line0) )
          set_device_name(device.c_str(), IORESP_ALL);
      }
      break;

    case processor_t::ev_newprc:
      if ( helper.supstr(&device, -1) > 0 )
        set_device_name(device.c_str(), IORESP_PORT);
      break;

    case processor_t::ev_creating_segm:
      {
        segment_t *s = va_arg(va, segment_t *);
        // Set default value of DS register for all segments
        set_default_dataseg(s->sel);
      }
      break;

    case processor_t::ev_out_header:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        C39_header(*ctx);
        return 1;
      }

    case processor_t::ev_out_footer:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        C39_footer(*ctx);
        return 1;
      }

    case processor_t::ev_out_segstart:
      {
        outctx_t *ctx = va_arg(va, outctx_t *);
        segment_t *seg = va_arg(va, segment_t *);
        C39_segstart(*ctx, seg);
        return 1;
      }

    case processor_t::ev_ana_insn:
      {
        insn_t *out = va_arg(va, insn_t *);
        return C39_ana(out);
      }

    case processor_t::ev_emu_insn:
      {
        const insn_t *insn = va_arg(va, const insn_t *);
        return C39_emu(*insn) ? 1 : -1;
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
        C39_data(*ctx, analyze_only);
        return 1;
      }

    default:
      break;
  }
  return 0;
}

//-----------------------------------------------------------------------
//      PseudoSam
//-----------------------------------------------------------------------
static const asm_t pseudosam =
{
  AS_COLON | AS_UDATA | ASH_HEXF3 | ASD_DECF0,
  // ���짮��⥫�᪨� 䫠���
  0,
  "Generic C39 assembler",              // �������� ��ᥬ����
  0,                                    // ����� � help'e
  NULL,                                 // ��⮧��������
  "org",                                // ��४⨢� ORG
  "end",                                // ��४⨢� end

  ";",                                  // ������਩
  '"',                                  // ࠧ����⥫� ��ப�
  '\'',                                 // ᨬ���쭠� ����⠭�
  "\\\"'",                              // ᯥ�ᨬ����

  "db",                                 // ascii string directive
  ".DATA.B",                             // byte directive
  ".DATA.W",                             // word directive
  ".DATA.L",                             // dword  (4 bytes)
  NULL,                                 // qword  (8 bytes)
  NULL,     // oword  (16 bytes)
  NULL,                                 // float  (4 bytes)
  NULL,                                 // double (8 bytes)
  NULL,                                 // tbyte  (10/12 bytes)
  NULL,                                 // packed decimal real
  "#d dup(#v)",                         // arrays (#h,#d,#v,#s(...)
  "db ?",                               // uninited arrays
  ".equ",                               // equ
  NULL,                                 // seg prefix
  "$",                                  // ����騩 IP
  NULL,                                 // ��������� �㭪樨
  NULL,                                 // ����� �㭪樨
  NULL,                                 // ��४⨢� public
  NULL,                                 // ��४⨢� weak
  NULL,                                 // ��४⨢� extrn
  NULL,                                 // ��४⨢� comm
  NULL,                                 // ������� ��� ⨯�
  ".ALIGN",                             // ���� align
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

// ���᮪ ��ᥬ���஢
static const asm_t *const asms[] = { &pseudosam, NULL };
//-----------------------------------------------------------------------
#define FAMILY "Rockwell C39:"
static const char *const shnames[] = { "C39", NULL };
static const char *const lnames[] = { FAMILY"Rockwell C39", NULL };

//--------------------------------------------------------------------------
// ���� �����⮢ �� �/�
static const uchar retcode_1[] = { 0x00, 0x0B };    // RTS
static const bytes_t retcodes[] =
{
  { sizeof(retcode_1), retcode_1 },
  { 0, NULL }
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH =
{
  IDP_INTERFACE_VERSION,  // version
  PLFM_C39,               // id ������
                          // flag
    PR_USE32
  | PR_BINMEM
  | PR_SEGTRANS,
                          // flag2
  0,
  8,                      // 8 bits in a byte for code segments
  8,                      // 8 bits in a byte

  shnames,                      // ���⪨� ����� �����஢ (�� 9 ᨬ�����)
  lnames,                       // ������ ����� �����஢

  asms,                         // ᯨ᮪ ��������஢

  notify,                       // �㭪�� �����饭��

  RegNames,                     // Regsiter names
  qnumber(RegNames),            // Number of registers

  rVcs,rVds,
  2,                            // size of a segment register
  rVcs,rVds,
  NULL,                         // ⨯��� ���� ��砫� �����
  retcodes,                     // ���� return'ov
  0,C39_last,                   // ��ࢠ� � ��᫥���� ������樨
  Instructions,                 // instruc
  3,                            // ࠧ��� tbyte - 24 ���
  {0,0,0,0},                    // ����� ������ � ������饩 �窮�
  0,                            // Icode ��� ������� ������
  NULL,                         // micro virtual mashine
};
