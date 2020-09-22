/*
 *      Interactive disassembler (IDA).
 *      Version 3.05
 *      Copyright (c) 1990-95 by Ilfak Guilfanov.
 *      ALL RIGHTS RESERVED.
 *                              FIDO:   2:5020/209
 *                              E-mail: ig@estar.msk.su
 *
 *      16.11.95 - MAR * generated unneeded xref.
 *
 */

#include "tms.hpp"

static int flow;
//------------------------------------------------------------------------
static void set_immd_bit(const insn_t &insn)
{
  set_immd(insn.ea);
  switch ( insn.itype )
  {
    case TMS_and:
    case TMS_bit:
    case TMS_bitt:
    case TMS_bsar:
    case TMS_cmpr:
    case TMS_in:
    case TMS_intr:
    case TMS_apl2:
    case TMS_opl2:
    case TMS_xpl2:
    case TMS_or:
    case TMS_rpt:
    case TMS_xc:
    case TMS_xor:
    case TMS_rptz:

    case TMS2_bit:
    case TMS2_in:
    case TMS2_out:
    case TMS2_andk:
    case TMS2_ork:
    case TMS2_xork:
    case TMS2_rptk:
      op_num(insn.ea, 0);
      break;
  }
}

//----------------------------------------------------------------------
int find_ar(const insn_t &insn, ea_t *res)
{
  ea_t ea = insn.ea;
  for ( int i=0; i < get_lookback(); i++ )
  {
    ea = prevInstruction(ea);
    if ( !is_code(get_flags(ea)) )
      break;
    ushort code = (ushort)get_wide_byte(ea);
    if ( isC2() )
    {
      switch ( code >> 11 )
      {
        case 6:                 // LAR
          return 0;
        case 0x18:              // LARK
          *res = map_data_ea(insn, code & 0xFF);
          return 1;
        case 0x1A:              // LRLK
          if ( (code & 0xF8FF) == 0xD000 )
          {
            ushort b = (ushort)get_wide_byte(ea+1);
            *res = map_data_ea(insn, b);
            return 1;
          }
      }
      continue;
    }
    switch ( code >> 11 )
    {
      case 0:                   // Load AR from addressed data
        return 0;               // LAR found, unknown address
      case 0x16:                // Load AR short immediate
        *res = map_data_ea(insn, code & 0xFF);
        return 1;
      case 0x17:                // Load AR long immediate
        if ( (code & ~7) == 0xBF08 )
        {
          ushort b = (ushort)get_wide_byte(ea+1);
          *res = map_data_ea(insn, b);
          return 1;
        }
    }
  }
  return 0;
}

//----------------------------------------------------------------------
static void handle_operand(const insn_t &insn, const op_t &x, bool isload)
{
  ea_t ea;
  switch ( x.type )
  {
    case o_phrase:                // 2 registers or indirect addressing
      if ( insn.itype != TMS_mar
        && insn.itype != TMS2_mar
        && find_ar(insn, &ea) )
      {
        goto SET_DREF;
      }
    case o_reg:
    case o_bit:
    case o_cond:
      break;
    case o_imm:
      {
        if ( !isload )
          goto badTouch;
        set_immd_bit(insn);
        flags_t F = get_flags(insn.ea);
        if ( op_adds_xrefs(F, x.n) )
          insn.add_off_drefs(x, dr_O, is_mpy(insn) ? OOF_SIGNED : 0);
      }
      break;
    case o_mem:
      ea = map_data_ea(insn, x);
SET_DREF:
      insn.create_op_data(ea, x);
      insn.add_dref(ea, x.offb, isload ? dr_R : dr_W);
      if ( x.type == o_mem )
      {
        if ( insn.itype == TMS_dmov
          || insn.itype == TMS_ltd
          || insn.itype == TMS_macd
          || insn.itype == TMS_madd
          || insn.itype == TMS2_dmov
          || insn.itype == TMS2_macd )
        {
          insn.add_dref(ea+1, x.offb, dr_W);
        }
      }
      break;
    case o_near:
      {
        ea = map_code_ea(insn, x);
        if ( insn.itype == TMS_blpd
          || insn.itype == TMS_mac
          || insn.itype == TMS_macd
          || insn.itype == TMS2_blkp
          || insn.itype == TMS2_mac
          || insn.itype == TMS2_macd )
        {
          goto SET_DREF;
        }
        ea_t segbase = (ea - x.addr) >> 4;
        uval_t thisseg = insn.cs;
        int iscall = has_insn_feature(insn.itype, CF_CALL);
        if ( insn.itype == TMS_rptb && is_tail(get_flags(ea)) )
        {
          // small hack to display end_loop-1 instead of before_end_loop+1
          ea++;
        }

        cref_t xtype = iscall
                     ? (segbase == thisseg ? fl_CN : fl_CF)
                     : (segbase == thisseg ? fl_JN : fl_JF);
        insn.add_cref(ea, x.offb, xtype);
        if ( iscall && !func_does_return(ea) )
          flow = false;
      }
      break;
    default:
badTouch:
      warning("%a: %s,%d: bad optype %d", insn.ea, insn.get_canon_mnem(), x.n, x.type);
      break;
  }
}

//----------------------------------------------------------------------
static int isDelayedStop(ushort code)
{
  switch ( code>>12 )
  {
    case 7:
      return (code & 0xFF00u) == 0x7D00u;
    case 0xB:
      return code == 0xBE21u;
    case 0xF:
      return (code & 0xEFFFu) == 0xEF00u;
  }
  return 0;
}

//----------------------------------------------------------------------
static bool can_flow(const insn_t &insn)
{
  if ( isC2() )
    return true;
  flags_t F = get_flags(insn.ea);
  if ( !is_flow(F) )
    return true;                                // no previous instructions
  ea_t ea = prevInstruction(insn.ea);
  if ( insn.size == 2 )                         // our instruction is long
  {
    ; // nothing to do
  }
  else
  {                                             // our instruction short
    if ( (insn.ea-ea) == 2 )                    // prev instruction long
      return true;                              // can flow always
    F = get_flags(ea);
    if ( !is_code(F) || !is_flow(F) )
      return true; // no prev instr...
    ea = prevInstruction(ea);
  }
  F = get_flags(ea);
  return !is_code(F) || !isDelayedStop((ushort)get_wide_byte(ea));
}

//----------------------------------------------------------------------
int idaapi emu(const insn_t &insn)
{
  uint32 Feature = insn.get_canon_feature();
  flow = ((Feature & CF_STOP) == 0);

  if ( Feature & CF_USE1 ) handle_operand(insn, insn.Op1, true);
  if ( Feature & CF_USE2 ) handle_operand(insn, insn.Op2, true);
  if ( Feature & CF_JUMP )
    remember_problem(PR_JUMP, insn.ea);

  if ( Feature & CF_CHG1 ) handle_operand(insn, insn.Op1, false);
  if ( Feature & CF_CHG2 ) handle_operand(insn, insn.Op2, false);

  if ( flow && can_flow(insn) )
    add_cref(insn.ea, insn.ea+insn.size, fl_F);

  switch ( insn.itype )
  {
    case TMS_ldp:                       // change DP register
    case TMS2_ldp:                      // change DP register
    case TMS2_ldpk:                     // change DP register
      {
        uint v = (insn.Op1.type == o_imm) ? uint(insn.Op1.value) : -1u;
        split_sreg_range(get_item_end(insn.ea), rDP, v, SR_auto);
      }
      break;
  }

  return 1;
}
