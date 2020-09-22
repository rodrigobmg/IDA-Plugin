
// Common include files for IDP modules:

#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <name.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <problems.hpp>
#include <lines.hpp>
#include <loader.hpp>
#include <offset.hpp>
#include <segment.hpp>
#include <kernwin.hpp>

// Current processor in the module
// It must be exported
idaman processor_t ida_module_data LPH;

void idaapi out_insn(outctx_t &ctx);
void idaapi out_mnem(outctx_t &ctx);
bool idaapi out_opnd(outctx_t &ctx, const op_t &x);

// use this define if the default out_mnem() is good enough
#define DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(CTXNAME)      \
  void idaapi out_insn(outctx_t &ctx)                   \
  {                                                     \
    CTXNAME *p = (CTXNAME *)&ctx;                       \
    p->out_insn();                                      \
  }                                                     \
  bool idaapi out_opnd(outctx_t &ctx, const op_t &x)    \
  {                                                     \
    CTXNAME *p = (CTXNAME *)&ctx;                       \
    return p->out_operand(x);                           \
  }

// use this define if you want to print insn mnemonics yourself
#define DECLARE_OUT_FUNCS(CTXNAME)                      \
  DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(CTXNAME)            \
  void idaapi out_mnem(outctx_t &ctx)                   \
  {                                                     \
    CTXNAME *p = (CTXNAME *)&ctx;                       \
    p->out_proc_mnem();                                 \
  }

//--------------------------------------------------------------------------
inline bool print_predefined_segname(
        outctx_t &ctx,
        qstring *sname,
        const char *const predefined[],
        size_t n)
{
  for ( size_t i=0; i < n; i++ )
  {
    if ( *sname == predefined[i] )
    {
      ctx.gen_printf(inf.indent, COLSTR("%s", SCOLOR_ASMDIR), sname->c_str());
      return true;
    }
  }
  validate_name(sname, VNT_IDENT);
  return false;
}

