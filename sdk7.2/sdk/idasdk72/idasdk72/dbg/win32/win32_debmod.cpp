#include <windows.h>
#include <fpro.h>
#include <err.h>
#include <ida.hpp>
#include <dbg.hpp>
#include <prodir.h>
#include <exehdr.h>
#include <kernwin.hpp>
#include <segment.hpp>
#include "win32_debmod.h"

//--------------------------------------------------------------------------

#ifndef TH32CS_SNAPNOHEAPS
  #define TH32CS_SNAPNOHEAPS    0x0
#endif
#include "win32_debmod_impl.cpp"
#define get_reg_class(reg_idx) get_x86_reg_class(reg_idx)

typedef HANDLE WINAPI OpenThread_t(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
static OpenThread_t *_OpenThread = NULL;
typedef HRESULT WINAPI GetThreadDescription_t(HANDLE hThread, PWSTR *threadDescription);
static GetThreadDescription_t *_GetThreadDescription = NULL;

#ifndef __X86__
typedef BOOL WINAPI Wow64GetThreadContext_t(HANDLE hThread, PWOW64_CONTEXT lpContext);
typedef BOOL WINAPI Wow64SetThreadContext_t(HANDLE hThread, const WOW64_CONTEXT *lpContext);
typedef BOOL WINAPI Wow64GetThreadSelectorEntry_t(HANDLE hThread, DWORD dwSelector, PWOW64_LDT_ENTRY lpSelectorEntry);
static Wow64GetThreadContext_t *_Wow64GetThreadContext = NULL;
static Wow64SetThreadContext_t *_Wow64SetThreadContext = NULL;
static Wow64GetThreadSelectorEntry_t *_Wow64GetThreadSelectorEntry = NULL;
#endif

//--------------------------------------------------------------------------
// Macro to test the DBG_FLAG_DONT_DISTURB flag
#if 0
#define NODISTURB_ASSERT(x) QASSERT(x)
#else
#define NODISTURB_ASSERT(x)
#endif

static int g_code = 0;

//--------------------------------------------------------------------------
void win32_debmod_t::check_thread(bool must_be_main_thread) const
{
  // remote debugger uses only one thread
  if ( rpc != NULL )
    return;

  // someone turned off debthread?
  if ( (debugger_flags & DBG_FLAG_DEBTHREAD) == 0 )
    return;

  // local debugger uses 2 threads and we must be in the correct one
  QASSERT(30191, is_main_thread() == must_be_main_thread);
}

//--------------------------------------------------------------------------
static int utf16_to_utf8(char *buf, size_t bufsize, LPCWSTR unicode)
{
  qstring res;
  utf16_utf8(&res, unicode);
  qstrncpy(buf, res.c_str(), bufsize);
  size_t n = res.length();
  if ( n > bufsize )
    n = bufsize;
  return (int)n;
}

//--------------------------------------------------------------------------
// try to locate full path of a dll name without full path
// for example, toolhelp.dll -> c:\windows\toolhelp.dll
static bool find_full_path(char *fname, size_t fnamesize, const char *process_path)
{
  if ( fname[0] != '\0' && !qisabspath(fname) )
  {
    char path[QMAXPATH];
    char dir[QMAXPATH];
    // check system directory
    GetSystemDirectory(dir, sizeof(dir));
    qmakepath(path, sizeof(path), dir, fname, NULL);
    if ( qfileexist(path) )
    {
FOUND:
      qstrncpy(fname, path, fnamesize);
      return true;
    }
    // check current process directory
    if ( process_path[0] != '\0' && !qisabspath(process_path) )
    {
      qdirname(dir, sizeof(dir), process_path);
      qmakepath(path, sizeof(path), dir, fname, NULL);
      if ( qfileexist(path) )
        goto FOUND;
    }
    // check current directory
    if ( GetCurrentDirectory(sizeof(dir), dir) != 0 )
    {
      qmakepath(path, sizeof(path), dir, fname, NULL);
      if ( qfileexist(path) )
        goto FOUND;
    }
    return false;
  }
  return true;
}

//--------------------------------------------------------------------------
ssize_t win32_debmod_t::access_memory(eanat_t ea, void *buffer, ssize_t size, bool do_write, bool suspend)
{
  if ( process_handle == INVALID_HANDLE_VALUE )
    return -1;

  NODISTURB_ASSERT(in_event != NULL || exiting);

  // stop all threads before accessing its memory
  if ( suspend )
    suspend_all_threads();

  ea = s0tops(ea);
  void *addr = (void *)ea;

  DWORD_PTR size_access = 0;
  const DWORD BADPROT = DWORD(-1);
  DWORD oldprotect = BADPROT;
  bool ok;

  while ( true )
  {
    // try to access the memory

    ok = do_write
       ? WriteProcessMemory(
           process_handle,     // handle of the process whose memory is accessed
           addr,               // address to start access
           buffer,             // address of buffer
           (DWORD)size,        // number of bytes to access
           (PDWORD_PTR)&size_access) != 0// address of number of bytes accessed
       : ReadProcessMemory(
           process_handle,     // handle of the process whose memory is accessed
           addr,               // address to start access
           buffer,             // address of buffer
           (DWORD)size,        // number of bytes to access
           (PDWORD_PTR)&size_access) != 0;// address of number of bytes accessed

    // if we have changed the page protection, revert it
    if ( oldprotect != BADPROT )
    {
      if ( !VirtualProtectEx(
              process_handle,     // handle of the process whose memory is accessed
              addr,               // address to start access
              (DWORD)size,        // number of bytes to access
              oldprotect,
              &oldprotect) )
      {
        deberr("VirtualProtectEx2(%p)", addr);
      }
      break; // do not attempt more than once
    }

    // bail out after a successful read/write
    if ( ok )
      break;

    // bail out if it is not about "not enough access rights"
    // *or* ERROR_PARTIAL_COPY as, sometimes we may read/write
    // *only* parts of memory because of page breakpoints
    int code = GetLastError();
    if ( code != ERROR_NOACCESS && code != ERROR_PARTIAL_COPY )
    {
      deberr("%sProcessMemory(%p)", do_write ? "Write" : "Read", ea);
      break;
    }

    if ( code != ERROR_PARTIAL_COPY )
      size_access = 0; // size_access may be spoiled after failed ReadProcessMemory

    // check if the address is valid
    MEMORY_BASIC_INFORMATION meminfo;
    if ( !VirtualQueryEx(process_handle,    // handle of process
                         addr,              // address of region
                         &meminfo,          // address of information buffer
                         sizeof(meminfo)) ) // size of buffer
    {
      size_access = 0;
      break;
    }

    // allow the desired access on the page
    if ( !VirtualProtectEx(
      process_handle,     // handle of the process whose memory is accessed
      addr,               // address to start access
      (DWORD)size,        // number of bytes to access
      do_write ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ,
      &oldprotect) )
    {
      deberr("VirtualProtectEx1(%08p, size=%d for %s)", ea, int(size), do_write ? "write" : "read");
      break;
    }
  }

  if ( do_write && ok )
    FlushInstructionCache(
      process_handle,      // handle to process with cache to flush
      addr,                // pointer to region to flush
      (DWORD)size);        // length of region to flush

  if ( suspend )
    resume_all_threads();
  return size_access;
}

//--------------------------------------------------------------------------
ssize_t win32_debmod_t::_read_memory(eanat_t ea, void *buffer, size_t size, bool suspend)
{
  return access_memory(ea, buffer, size, false, suspend);
}

ssize_t idaapi win32_debmod_t::dbg_read_memory(ea_t ea, void *buffer, size_t size, qstring * /*errbuf*/)
{
  check_thread(false);
  return _read_memory(ea, buffer, size, true);
}

//--------------------------------------------------------------------------
// Make sure that the thread is suspended
// by calling SuspendThread twice
// If raw=true then SuspendThread() API will be called and we return directly
// without doing any further logic
static void _sure_suspend_thread(thread_info_t &ti, bool raw = false)
{
  HANDLE h = ti.hThread;

  int count = SuspendThread(h);
  if ( raw )
    return;

  if ( count != -1 )
    ti.suspend_count++;

  count = SuspendThread(h);
  if ( count != -1 )
    ti.suspend_count++;
}

//--------------------------------------------------------------------------
// Resume thread by calling ResumeThread as many times as required
// Note: this function just reverts the actions of sure_suspend_thread
// If the thread was already suspended before calling sure_suspend_thread
// then it will stay in the suspended state
// If raw=true then ResumeThread() will be called and we return directly
// without doing any further logic
static void _sure_resume_thread(thread_info_t &ti, bool raw = false)
{
  HANDLE h = ti.hThread;
  if ( raw )
  {
    ResumeThread(h);
    return;
  }

  while ( ti.suspend_count > 0 )
  {
    ResumeThread(h);
    ti.suspend_count--;
  }
}

//--------------------------------------------------------------------------
inline void win32_debmod_t::suspend_all_threads(bool raw)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    _sure_suspend_thread(p->second, raw);
}

//--------------------------------------------------------------------------
inline void win32_debmod_t::resume_all_threads(bool raw)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    _sure_resume_thread(p->second, raw);
}

//--------------------------------------------------------------------------
static int get_thread_suspend_count(HANDLE hThread)
{
  DWORD dwSuspendCount = SuspendThread(hThread);
  ResumeThread(hThread);
  return dwSuspendCount;
}

//--------------------------------------------------------------------------
inline void win32_debmod_t::suspend_running_threads(threadvec_t &suspended)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    thread_info_t t = p->second;
    t.suspend_count = get_thread_suspend_count(t.hThread);
    if ( t.suspend_count == 0 )
    {
      _sure_suspend_thread(t);
      suspended.push_back(t);
    }
  }
}

//--------------------------------------------------------------------------
inline void win32_debmod_t::resume_suspended_threads(threadvec_t suspended) const
{
  threadvec_t::iterator p;
  for ( p = suspended.begin(); p != suspended.end(); ++p )
    _sure_resume_thread(*p);
}

//--------------------------------------------------------------------------
size_t win32_debmod_t::add_dll(image_info_t &ii)
{
  dlls.insert(std::make_pair(ii.base, ii));
  dlls_to_import.insert(ii.base);
  return (size_t)ii.imagesize;
}

//--------------------------------------------------------------------------
// iterate all modules of the specified process
// until the callback returns != 0
int win32_debmod_t::for_each_module(DWORD _pid, module_cb_t module_cb, void *ud)
{
  int code = 0;

  module_snapshot_t msnap(get_tool_help());
  MODULEENTRY32 me;
  for ( bool ok = msnap.first(TH32CS_SNAPNOHEAPS, _pid, &me); ok; ok = msnap.next(&me) )
  {
    code = module_cb(this, &me, ud);
    if ( code != 0 )
      break;
  }
  return code;
}

//--------------------------------------------------------------------------
// callback: get info about the main module of the debugger process
//lint -e{818}
int win32_debmod_t::get_dmi_cb(debmod_t *sess, MODULEENTRY32 *me32, void *ud)
{
  win32_debmod_t *_this = (win32_debmod_t *)sess;
  // if the module name doesn't correspond to the process name,
  // we continue to iterate
  char buf[QMAXPATH];
  tchar_utf8(buf, me32->szModule, sizeof(buf));
  if ( !_this->process_path.empty() && stricmp(buf, qbasename(_this->process_path.c_str())) != 0 )
    return 0;

  // ok, this module corresponds to our debugged process
  modinfo_t &dmi = *(modinfo_t *)ud;
  dmi.name = _this->process_path;
  dmi.base = EA_T(me32->modBaseAddr);
  dmi.size = (asize_t)me32->modBaseSize;
  return 1; // we stop to iterate
}

//--------------------------------------------------------------------------
// Return module information on the currently debugged process
void win32_debmod_t::get_debugged_module_info(modinfo_t *dmi)
{
  dmi->name[0]   = '\0';
  dmi->base      = BADADDR;
  dmi->size      = 0;
  dmi->rebase_to = BADADDR;
  for_each_module(pid, get_dmi_cb, dmi);
}

//--------------------------------------------------------------------------
void idaapi win32_debmod_t::dbg_stopped_at_debug_event(
        import_infos_t *,
        bool dlls_added,
        thread_name_vec_t *thr_names)
{
  if ( dlls_added )
  {
    check_thread(true);
    // we will take advantage of this event to import information
    // about the exported functions from the loaded dlls and the
    // binary itself
    name_info_t &ni = *get_debug_names();
    if ( !binary_to_import.name.empty() )
    {
      const char *bin_path = binary_to_import.name.c_str();
      linput_t *li = open_linput(bin_path, false);
      if ( li != NULL )
      {
        get_pe_exports_from_path(bin_path, li, binary_to_import.base, ni);
        close_linput(li);
      }
      binary_to_import.name.clear();
    }

    for ( easet_t::iterator p = dlls_to_import.begin(); p != dlls_to_import.end(); )
    {
      get_dll_exports(dlls, *p, ni);
      p = dlls_to_import.erase(p);
    }
  }

  if ( thr_names != NULL )
    update_thread_names(thr_names);
}

//--------------------------------------------------------------------------
static void update_thread_description(thread_info_t &ti)
{
  if ( _GetThreadDescription == NULL )
    return;

  PWSTR data;
  HRESULT hr = _GetThreadDescription(ti.hThread, &data);
  if ( SUCCEEDED(hr) )
  {
    int data_sz = wcslen(data) * 2;   // size in bytes
    qstring newname;
    if ( convert_encoding(
                    (bytevec_t*)&newname,
                    ENC_UTF16LE, ENC_UTF8,
                    (const uchar *)data,
                    data_sz) > 0 )
    {
      if ( newname != ti.name )
      {
        ti.name = newname.c_str();  // newname over allocated
        ti.set_new_name();
      }
    }
    LocalFree(data);
  }
}

//--------------------------------------------------------------------------
void win32_debmod_t::update_thread_names(thread_name_vec_t *thr_names)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    thread_info_t &ti = p->second;
    update_thread_description(ti);
    if ( ti.is_new_name() )
    {
      thread_name_t &tn = thr_names->push_back();
      tn.tid = ti.tid;
      tn.name = ti.name;
      ti.clr_new_name();
    }
  }
}

//--------------------------------------------------------------------------
// return the address of an exported name
ea_t win32_debmod_t::get_dll_export(
        const images_t &_dlls,
        ea_t imagebase,
        const char *exported_name)
{
  ea_t ret = BADADDR;

  name_info_t ni;
  if ( get_dll_exports(_dlls, imagebase, ni, exported_name) && !ni.addrs.empty() )
    ret = ni.addrs[0];
  return ret;
}

//--------------------------------------------------------------------------
win32_debmod_t::win32_debmod_t()
  : expecting_debug_break(0), stop_at_ntdll_bpts(false)
{
  fake_suspend_event = false;

  pid = -1;

  // Reset handles
  process_handle  = INVALID_HANDLE_VALUE;
  thread_handle   = INVALID_HANDLE_VALUE;
  redirin_handle  = INVALID_HANDLE_VALUE;
  redirout_handle = INVALID_HANDLE_VALUE;

  attach_evid = INVALID_HANDLE_VALUE;
  attach_status = as_none;

  memset(&cpdi, 0, sizeof(cpdi));
  cpdi.hFile = INVALID_HANDLE_VALUE;  // hFile
  cpdi.hProcess = INVALID_HANDLE_VALUE;  // hProcess
  cpdi.hThread = INVALID_HANDLE_VALUE;  // hThread

  winxp_step_thread = 0;
  memset(&in_event, 0, sizeof(in_event));
  exiting = false;
  pause_requested = false;

  broken_event_handle = NULL;
  // we don't set platform name here because it will be inherited
  // from winbase_debmod_t

  binary_to_import.base = BADADDR;
  binary_to_import.size = 0;
  binary_to_import.rebase_to = BADADDR;
}

//----------------------------------------------------------------------
// return the handle associated with a thread id from the threads list
HANDLE win32_debmod_t::get_thread_handle(thid_t tid)
{
  thread_info_t *tinfo = threads.get(tid);
  return tinfo == NULL ? INVALID_HANDLE_VALUE : tinfo->hThread;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::refresh_hwbpts(void)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    set_hwbpts(p->second.hThread);
  return true;
}

//--------------------------------------------------------------------------
// 1-ok, 0-failed
int idaapi win32_debmod_t::dbg_del_bpt(bpttype_t type, ea_t ea, const uchar *orig_bytes, int len)
{
  check_thread(false);
  if ( orig_bytes != NULL )
  {
    bool ok = false;
    bpts.erase(ea);
    suspend_all_threads();
    // write the old value only if our bpt is still present
    if ( !has_bpt_at(ea) )
    {
      if ( !exiting )
        dmsg("%a: breakpoint vanished from memory\n", ea);
      ok = true;
    }
    else
    {
      ok = _write_memory(ea, orig_bytes, len) == len;
    }
    resume_all_threads();
    return ok;
  }

  // try to delete a page bpt first
  if ( del_page_bpt(ea, type) )
    return true;
  return del_hwbpt(ea, type);
}

//--------------------------------------------------------------------------
ssize_t win32_debmod_t::_write_memory(eanat_t ea, const void *buffer, size_t size, bool suspend)
{
  if ( !may_write(ea) )
    return -1;
  return access_memory(ea, (void *)buffer, size, true, suspend);
}

//--------------------------------------------------------------------------
void idaapi win32_debmod_t::dbg_term(void)
{
  check_thread(true);
  cleanup_hwbpts();
  cleanup();
  for ( size_t i = 0; i < pdb_remote_sessions.size(); ++i )
    close_pdb_remote_session(pdb_remote_sessions[i]);
  inherited::dbg_term();
}

//--------------------------------------------------------------------------
bool win32_debmod_t::has_bpt_at(ea_t ea)
{
  uchar bytes[8];
  int size = bpt_code.size();
  return _read_memory(ea, bytes, size) == size
      && memcmp(bytes, bpt_code.begin(), size) == 0;
}

//--------------------------------------------------------------------------
// 2-ok(pagebpt), 1-ok, 0-failed, -2-read failed
int idaapi win32_debmod_t::dbg_add_bpt(
        bytevec_t *orig_bytes,
        bpttype_t type,
        ea_t ea,
        int len)
{
  check_thread(false);
  if ( type == BPT_SOFT )
  {
    if ( orig_bytes != NULL && read_bpt_orgbytes(orig_bytes, ea, len) < 0 )
      return -2;
    int size = bpt_code.size();
    debmod_bpt_t dbpt(ea, len);
    if ( dbg_read_memory(ea, dbpt.saved, len, NULL)
      && dbg_write_memory(ea, bpt_code.begin(), size, NULL) != size )
    {
      return false;
    }
    bpts[ea] = dbpt;
    return true;
  }

  // try, first, to add a real hw breakpoint
  // if it fails, add a memory range type bpt
  // reason: the user may try to insert a 5th
  // correct hw bpt, however, it isn't possible
  // so, instead, we add a page breakpoint
  int ret = 0;
  if ( check_x86_hwbpt(type, ea, len) == BPT_OK )
    ret = add_hwbpt(type, ea, len);

  if ( !ret )
    ret = dbg_add_page_bpt(type, ea, len);
  return ret;
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_get_memory_info(meminfo_vec_t &ranges, qstring * /*errbuf*/)
{
  check_thread(false);
  NODISTURB_ASSERT(in_event != NULL);

  images.clear();
  thread_ranges.clear();
  class_ranges.clear();
  for ( threads_t::iterator t=threads.begin(); t != threads.end(); ++t )
    add_thread_ranges(t->first, thread_ranges, class_ranges);

  if ( process_handle != INVALID_HANDLE_VALUE )
  {
    for ( ea_t ea=0; ea != BADADDR; )
    {
      memory_info_t meminf;
      ea = get_region_info(ea, &meminf);
      if ( ea != BADADDR && meminf.start_ea != BADADDR )
        ranges.push_back(meminf);
    }
    enable_page_bpts(true);
  }

  if ( same_as_oldmemcfg(ranges) )
    return DRC_NOCHG;

  save_oldmemcfg(ranges);
  return DRC_OK;
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_thread_suspend(thid_t tid)
{
  check_thread(false);
  NODISTURB_ASSERT(in_event != NULL);
  int count = SuspendThread(get_thread_handle(tid));
  if ( count == -1 )
    deberr("SuspendThread(%08X)", tid);

  if ( debug_debugger )
    debdeb("SuspendThread(%08X) -> %d\n", tid, count);

  return count != -1 ? DRC_OK : DRC_FAILED;
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_thread_continue(thid_t tid)
{
  check_thread(false);
  NODISTURB_ASSERT(in_event != NULL);
  int count = ResumeThread(get_thread_handle(tid));
  if ( count == -1 )
    deberr("ResumeThread(%08X)", tid);

  if ( debug_debugger )
    debdeb("ResumeThread(%08X) -> %d\n", tid, count);

  return count != -1 ? DRC_OK : DRC_FAILED;
}

//--------------------------------------------------------------------------
static int calc_ctxflags(int clsmask)
{
  int ctxflags = CONTEXT_CONTROL|CONTEXT_INTEGER;
#ifdef __ARM__
  qnotused(clsmask);
#else
  if ( (clsmask & X86_RC_SEGMENTS) != 0 )
    ctxflags |= CONTEXT_SEGMENTS;
  if ( (clsmask & (X86_RC_FPU|X86_RC_MMX)) != 0 )
    ctxflags |= CONTEXT_FLOATING_POINT;
  if ( (clsmask & X86_RC_XMM) != 0 )
#ifndef __X86__
    ctxflags |= CONTEXT_FLOATING_POINT;
#else
    ctxflags |= CONTEXT_EXTENDED_REGISTERS;
#endif
#endif
  return ctxflags;
}

//--------------------------------------------------------------------------
// assertions that ensure that the conversion between CONTEXT and WOW64_CONTEXT
// is correct
#ifdef __X86__
#ifndef __ARM__
CASSERT(sizeof(FLOATING_SAVE_AREA) == 112);
CASSERT(CONTEXT_CONTROL                   == 0x10001);
CASSERT(CONTEXT_INTEGER                   == 0x10002);
CASSERT(CONTEXT_SEGMENTS                  == 0x10004);
CASSERT(CONTEXT_FLOATING_POINT            == 0x10008);
CASSERT(CONTEXT_DEBUG_REGISTERS           == 0x10010);
CASSERT(CONTEXT_EXTENDED_REGISTERS        == 0x10020);
#endif
#else
CASSERT(sizeof(WOW64_FLOATING_SAVE_AREA) == 112);
CASSERT(sizeof(XSAVE_FORMAT) == WOW64_MAXIMUM_SUPPORTED_EXTENSION);
CASSERT(WOW64_CONTEXT_CONTROL             == 0x10001);
CASSERT(WOW64_CONTEXT_INTEGER             == 0x10002);
CASSERT(WOW64_CONTEXT_SEGMENTS            == 0x10004);
CASSERT(WOW64_CONTEXT_FLOATING_POINT      == 0x10008);
CASSERT(WOW64_CONTEXT_DEBUG_REGISTERS     == 0x10010);
CASSERT(WOW64_CONTEXT_EXTENDED_REGISTERS  == 0x10020);
#endif

#ifndef __X86__
#undef Esp
#undef Eip
//--------------------------------------------------------------------------
inline int ctxflags_to_wow64(int ctxflags)
{
  if ( (ctxflags & CONTEXT_FLOATING_POINT) != 0 )
    ctxflags |= WOW64_CONTEXT_EXTENDED_REGISTERS;
  return ctxflags; // see CASSERTs anout CONTEXT_... bits above
}

//--------------------------------------------------------------------------
void thread_info_t::cvt_from_wow64(const WOW64_CONTEXT &wow64ctx, int clsmask)
{
  ctx.ContextFlags = calc_ctxflags(clsmask);

  ctx.Dr0 = wow64ctx.Dr0;
  ctx.Dr1 = wow64ctx.Dr1;
  ctx.Dr2 = wow64ctx.Dr2;
  ctx.Dr3 = wow64ctx.Dr3;
  ctx.Dr6 = wow64ctx.Dr6;
  ctx.Dr7 = wow64ctx.Dr7;

  ctx.SegGs = wow64ctx.SegGs;
  ctx.SegFs = wow64ctx.SegFs;
  ctx.SegEs = wow64ctx.SegEs;
  ctx.SegDs = wow64ctx.SegDs;

  ctx.Rdi = wow64ctx.Edi;
  ctx.Rsi = wow64ctx.Esi;
  ctx.Rbx = wow64ctx.Ebx;
  ctx.Rdx = wow64ctx.Edx;
  ctx.Rcx = wow64ctx.Ecx;
  ctx.Rax = wow64ctx.Eax;

  ctx.Rbp    = wow64ctx.Ebp;
  ctx.SegCs  = wow64ctx.SegCs;
  ctx.EFlags = wow64ctx.EFlags;
  ctx.SegSs  = wow64ctx.SegSs;
  ctx.Rip    = wow64ctx.Eip;
  ctx.Rsp    = wow64ctx.Esp;

  if ( (wow64ctx.ContextFlags & WOW64_CONTEXT_EXTENDED_REGISTERS) != 0 )
  {
    memcpy(&ctx.FltSave, wow64ctx.ExtendedRegisters, sizeof(ctx.FltSave));
  }
  else if ( (wow64ctx.ContextFlags & WOW64_CONTEXT_FLOATING_POINT) != 0 )
  {
    ctx.FltSave.ControlWord   = wow64ctx.FloatSave.ControlWord;
    ctx.FltSave.StatusWord    = wow64ctx.FloatSave.StatusWord;
    ctx.FltSave.TagWord       = wow64ctx.FloatSave.TagWord;
    ctx.FltSave.ErrorOffset   = wow64ctx.FloatSave.ErrorOffset;
    ctx.FltSave.ErrorSelector = wow64ctx.FloatSave.ErrorSelector;
    ctx.FltSave.DataOffset    = wow64ctx.FloatSave.DataOffset;
    ctx.FltSave.DataSelector  = wow64ctx.FloatSave.DataSelector;
    memset(ctx.FltSave.FloatRegisters, 0, sizeof(ctx.FltSave.FloatRegisters));
    for ( int i=0; i < 8; i++ )
      memcpy(&ctx.FltSave.FloatRegisters[i], &wow64ctx.FloatSave.RegisterArea[i*10], 10);
  }
}

//--------------------------------------------------------------------------
void thread_info_t::cvt_to_wow64(WOW64_CONTEXT *wow64ctx, int clsmask) const
{
  int cflags = calc_ctxflags(clsmask);
  int wflags = ctxflags_to_wow64(cflags);
  wow64ctx->ContextFlags = wflags;

  wow64ctx->Dr0 = ctx.Dr0;
  wow64ctx->Dr1 = ctx.Dr1;
  wow64ctx->Dr2 = ctx.Dr2;
  wow64ctx->Dr3 = ctx.Dr3;
  wow64ctx->Dr6 = ctx.Dr6;
  wow64ctx->Dr7 = ctx.Dr7;

  wow64ctx->SegGs = ctx.SegGs;
  wow64ctx->SegFs = ctx.SegFs;
  wow64ctx->SegEs = ctx.SegEs;
  wow64ctx->SegDs = ctx.SegDs;

  wow64ctx->Edi = ctx.Rdi;
  wow64ctx->Esi = ctx.Rsi;
  wow64ctx->Ebx = ctx.Rbx;
  wow64ctx->Edx = ctx.Rdx;
  wow64ctx->Ecx = ctx.Rcx;
  wow64ctx->Eax = ctx.Rax;

  wow64ctx->Ebp    = ctx.Rbp;
  wow64ctx->SegCs  = ctx.SegCs;
  wow64ctx->EFlags = ctx.EFlags;
  wow64ctx->SegSs  = ctx.SegSs;
  wow64ctx->Eip    = ctx.Rip;
  wow64ctx->Esp    = ctx.Rsp;

  if ( (wflags & WOW64_CONTEXT_FLOATING_POINT) != 0 )
  {
    wow64ctx->FloatSave.ControlWord   = ctx.FltSave.ControlWord;
    wow64ctx->FloatSave.StatusWord    = ctx.FltSave.StatusWord;
    wow64ctx->FloatSave.TagWord       = ctx.FltSave.TagWord;
    wow64ctx->FloatSave.ErrorOffset   = ctx.FltSave.ErrorOffset;
    wow64ctx->FloatSave.ErrorSelector = ctx.FltSave.ErrorSelector;
    wow64ctx->FloatSave.DataOffset    = ctx.FltSave.DataOffset;
    wow64ctx->FloatSave.DataSelector  = ctx.FltSave.DataSelector;
    for ( int i=0; i < 8; i++ )
      memcpy(&wow64ctx->FloatSave.RegisterArea[i*10], &ctx.FltSave.FloatRegisters[i], 10);
  }
  if ( (wflags & WOW64_CONTEXT_EXTENDED_REGISTERS) != 0 )
    memcpy(wow64ctx->ExtendedRegisters, &ctx.FltSave, sizeof(ctx.FltSave));
}

#define Eip Rip
#endif

//--------------------------------------------------------------------------
bool thread_info_t::read_context(int clsmask)
{
  if ( (flags & clsmask) == clsmask )
    return true;

  int ctxflags = calc_ctxflags(clsmask);
#ifndef __X86__
  if ( (flags & THR_WOW64) != 0 && _Wow64GetThreadContext != NULL )
  {
    WOW64_CONTEXT wow64ctx;
    wow64ctx.ContextFlags = ctxflags_to_wow64(ctxflags);
    if ( !_Wow64GetThreadContext(hThread, &wow64ctx) )
      return false;
    invalidate_context();
    cvt_from_wow64(wow64ctx, clsmask);
  }
  else
#endif
  {
    ctx.ContextFlags = ctxflags;
    if ( !GetThreadContext(hThread, &ctx) )
      return false;
    invalidate_context();
    ctx.ContextFlags = ctxflags; // invalidate_context() zeroed it
  }
  flags |= (clsmask | RC_GENERAL) & THR_CLSMASK;
  return true;
}

//--------------------------------------------------------------------------
bool thread_info_t::write_context(int clsmask)
{
#ifndef __X86__
  if ( (flags & THR_WOW64) != 0 && _Wow64SetThreadContext != NULL )
  {
    WOW64_CONTEXT wow64ctx;
    cvt_to_wow64(&wow64ctx, clsmask);
    return _Wow64SetThreadContext(hThread, &wow64ctx) != 0;
  }
#else
  qnotused(clsmask);
#endif
  return SetThreadContext(hThread, &ctx) != 0;
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_prepare_to_pause_process(qstring * /*errbuf*/)
{
  check_thread(false);
  bool ok = true;
  win_tool_help_t *wth = get_tool_help();
  if ( wth->use_debug_break_process() ) // only possible on XP/2K3 or higher
  {
    ok = wth->debug_break_process(process_handle);
    if ( !stop_at_ntdll_bpts )
      expecting_debug_break = ok;
  }
  else if ( threads.empty() )
  {
    ok = false;
  }
  else
  {
    suspend_all_threads();
    for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    {
      thread_info_t &ti = p->second;
      if ( !ti.read_context(RC_GENERAL) )
      {
        ok = false;
        continue;
      }
      // we have a problem: it is possible that eip points past a temporary breakpoint
      // that will be removed and replaced by the original instruction opcode.
      // if we set a new breakpoint now, it will be at the second byte of the
      // instruction and will lead to a crash.
      eanat_t ip = ti.ctx.Eip;
      if ( bpts.find(ip-bpt_code.size()) != bpts.end() )
        continue; // yes, there is a breakpoint just before us. it was just hit
                  // but hopefully not processed yet
      if ( !set_thread_bpt(ti, ip) )
        ok = false;
    }
    // send WM_NULL to the main thread, hopefully it will wake up the application
    thread_info_t &ti = threads.begin()->second;
    PostThreadMessageA(ti.tid, WM_NULL, 0, 0);
    resume_all_threads();
  }
  pause_requested = true;
  return ok ? DRC_OK : DRC_FAILED;
}

//----------------------------------------------------------------------
// return the name associated with an existing image in 'images' list
// containing a particular range
static const char *get_range_name(const images_t &images, const range_t *range)
{
  for ( images_t::const_iterator p=images.begin(); p != images.end(); ++p )
  {
    const image_info_t &img = p->second;
    ea_t ea1 = (ea_t)img.base;
    ea_t ea2 = ea1 + img.imagesize;
    range_t b = range_t(ea1, ea2);
    b.intersect(*range);
    if ( !b.empty() )
      return img.name.c_str();
  }
  return NULL;
}

//--------------------------------------------------------------------------
void win32_debmod_t::restore_original_bytes(ea_t ea, bool really_restore)
{
  bpt_info_t::iterator p = thread_bpts.find(ea);
  QASSERT(1488, p != thread_bpts.end());
  if ( --p->second.count == 0 )
  {
    uchar *obytes = p->second.orig_bytes;
    if ( really_restore )
    {
      int size = bpt_code.size();
      if ( _write_memory(ea, obytes, size) != size )
        INTERR(1489);
    }
    thread_bpts.erase(p);
  }
}

//--------------------------------------------------------------------------
// returns: 0-error,1-ok,2-already had bpt, just increased the counter
int win32_debmod_t::save_original_bytes(ea_t ea)
{
  bpt_info_t::iterator p = thread_bpts.find(ea);
  if ( p == thread_bpts.end() )
  {
    internal_bpt_info_t ibi;
    ibi.count = 1;
    int size = bpt_code.size();
    if ( _read_memory(ea, ibi.orig_bytes, size) != size )
      return 0;
    thread_bpts.insert(std::make_pair(ea, ibi));
    return 1;
  }
  else
  {
    p->second.count++;
    return 2;
  }
}

//--------------------------------------------------------------------------
bool win32_debmod_t::del_thread_bpt(thread_info_t &ti, ea_t ea)
{
  if ( ti.bpt_ea == BADADDR )
    return false;

  if ( ti.bpt_ea == ea )
  {
    if ( !ti.read_context(RC_GENERAL) )
      return false;
    ti.ctx.Eip = ti.bpt_ea; // reset EIP
    DWORD saved = ti.ctx.ContextFlags;
    ti.ctx.ContextFlags = CONTEXT_CONTROL;
    if ( !ti.write_context(RC_GENERAL) )
      deberr("del_thread_bpt: SetThreadContext");
    ti.ctx.ContextFlags = saved;
  }

  // restore old insn if necessary
  restore_original_bytes(ti.bpt_ea);
  ti.bpt_ea = BADADDR;
  return true;
}

//--------------------------------------------------------------------------
// delete all thread breakpoints
// returns true if a breakpoint at which we stopped was removed
bool win32_debmod_t::del_thread_bpts(ea_t ea)
{
  bool found = false;
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    found |= del_thread_bpt(p->second, ea);
  return found;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::set_thread_bpt(thread_info_t &ti, ea_t ea)
{
  // delete old thread bpt if any existed before
  del_thread_bpt(ti, BADADDR);

  ti.bpt_ea = ea;
  int code = save_original_bytes(ti.bpt_ea);
  if ( code )
  {
    if ( code == 2 ) // already have a bpt?
      return true;   // yes, then everything ok
    int size = bpt_code.size();
    code = _write_memory(ti.bpt_ea, bpt_code.begin(), size);
    if ( code > 0 )
    {
      if ( code == size )
        return true;
      // failed to write, forget the original byte
      restore_original_bytes(ti.bpt_ea, false);
    }
  }
  debdeb("%a: set_thread_bpt() failed to pause thread %d\n", ti.bpt_ea, ti.tid);
  ti.bpt_ea = BADADDR;
  return false;
}

//--------------------------------------------------------------------------
void win32_debmod_t::add_thread(const CREATE_THREAD_DEBUG_INFO &thr_info, thid_t tid)
{
#ifdef __ARM__
  wow64_state_t w = WOW64_NO;
#else
  wow64_state_t w = check_wow64_process();
#endif
  thread_info_t ti(thr_info, tid, w);
  threads.insert(std::make_pair(tid, ti));
}

//--------------------------------------------------------------------------
gdecode_t win32_debmod_t::get_debug_event(debug_event_t *event, int timeout_ms)
{
  check_thread(false);
  if ( events.retrieve(event) )
    return events.empty() ? GDE_ONE_EVENT : GDE_MANY_EVENTS;

  DEBUG_EVENT DebugEvent;
  // we have to wait infinitely if we just try to attach to a running process
  if ( attach_status == as_attaching )
    timeout_ms = INFINITE;
  if ( !WaitForDebugEvent(&DebugEvent, timeout_ms) )
  {
    // no event occurred
    if ( attach_status == as_detaching ) // if we were requested to detach,
    {                                    // we generate a fake detach event
      event->set_eid(PROCESS_DETACHED);
      return GDE_ONE_EVENT;
    }
    // else, we don't return an event
    return GDE_NO_EVENT;
  }

  if ( attach_status == as_attaching )
  {
    if ( DebugEvent.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT )
      return GDE_ERROR;
    // fill in starting information for the just attached process (we couldn't do it from CreateProcess() return values !)
    process_path   = "";
    pid            = DebugEvent.dwProcessId;
    attach_status  = as_breakpoint;
  }

  if ( debug_debugger )
    show_debug_event(DebugEvent);

  // ignore events coming from other child processes
  if ( DebugEvent.dwProcessId != pid )
  {
    debdeb("ignore: pid %x != %x\n", DebugEvent.dwProcessId, pid);
    bool handled = DebugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
      && (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT
       || DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_WX86_BREAKPOINT);

    if ( !ContinueDebugEvent(DebugEvent.dwProcessId,
      DebugEvent.dwThreadId,
      handled ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED) )
    {
      deberr("ContinueDebugEvent");
    }
    invalidate_all_contexts();
    return GDE_NO_EVENT;
  }

  event->pid = DebugEvent.dwProcessId;
  event->tid = DebugEvent.dwThreadId;
  event->handled = true;

  gdecode_t gdecode = GDE_ONE_EVENT;
  switch ( DebugEvent.dwDebugEventCode )
  {
    case EXCEPTION_DEBUG_EVENT:
      {
        EXCEPTION_RECORD &er = DebugEvent.u.Exception.ExceptionRecord;
        // remove temporary breakpoints if any
        bool was_thread_bpt = del_thread_bpts(EA_T(er.ExceptionAddress));
        bool firsttime = DebugEvent.u.Exception.dwFirstChance != 0;
        gdecode = handle_exception(event, er, was_thread_bpt, firsttime);
      }
      break;

    case CREATE_THREAD_DEBUG_EVENT:
      {
        // add this thread to our list
        add_thread(DebugEvent.u.CreateThread, event->tid);
        event->set_info(THREAD_STARTED);
        event->ea = EA_T(DebugEvent.u.CreateThread.lpStartAddress);
        // set hardware breakpoints if any
        set_hwbpts(DebugEvent.u.CreateThread.hThread);
      }
      break;

    case CREATE_PROCESS_DEBUG_EVENT:
      {
        // save information for later
        cpdi = DebugEvent.u.CreateProcessInfo;
        cpdi.lpBaseOfImage = correct_exe_image_base(cpdi.lpBaseOfImage);
        if ( process_handle != INVALID_HANDLE_VALUE && process_handle != cpdi.hProcess )
          myCloseHandle(process_handle); // already have an open handle
        process_handle = cpdi.hProcess;

        create_start_event(event);
        curproc.insert(std::make_pair(event->modinfo().base, image_info_t(this, event->modinfo())));

        // add record about the main thread into the list
        CREATE_THREAD_DEBUG_INFO ctdi;
        ctdi.hThread           = cpdi.hThread;
        ctdi.lpThreadLocalBase = cpdi.lpThreadLocalBase;
        ctdi.lpStartAddress    = cpdi.lpStartAddress;
        add_thread(ctdi, DebugEvent.dwThreadId);

        // set hardware breakpoints if any
        set_hwbpts(cpdi.hThread);

        // test hardware breakpoints:
        // add_hwbpt(HWBPT_WRITE, 0x0012FF68, 4);
        if ( highdlls.empty() && winver.is_DW32() ) // dw32 specific
        {
          HINSTANCE h = GetModuleHandle(kernel32_dll);
          eanat_t addr = eanat_t(h);
          uint32 size = calc_imagesize(addr);
          highdlls.add(addr, size);
        }
        break;
      }

    case EXIT_THREAD_DEBUG_EVENT:
      {
        threads.erase(event->tid);
        event->set_exit_code(THREAD_EXITED, DebugEvent.u.ExitThread.dwExitCode);
        // invalidate corresponding handles
        HANDLE h = get_thread_handle(event->tid);
        if ( h == thread_handle )
          thread_handle = INVALID_HANDLE_VALUE;
        if ( h == cpdi.hThread )
          cpdi.hThread = INVALID_HANDLE_VALUE;
        break;
      }

    case EXIT_PROCESS_DEBUG_EVENT:
      event->set_exit_code(PROCESS_EXITED, DebugEvent.u.ExitProcess.dwExitCode);
      exiting = true;
      break;

    case LOAD_DLL_DEBUG_EVENT:
      {
        const LOAD_DLL_DEBUG_INFO &dil = DebugEvent.u.LoadDll;
        eanat_t addr = eanat_t(dil.lpBaseOfDll);
        modinfo_t &mi_ll = event->set_modinfo(LIB_LOADED);
        event->ea = addr;
        mi_ll.base = event->ea;
        mi_ll.rebase_to = BADADDR; // this must be determined locally - see common_local.cpp

        char full_name[MAXSTR];
        full_name[0] = '\0';
        get_filename_for(
          full_name,
          sizeof(full_name),
          eanat_t(dil.lpImageName),
          dil.fUnicode != 0,
          addr);

        mi_ll.name = full_name;
        uint32 size = calc_imagesize(addr);
        mi_ll.size = size;

        // does the address fit into ea_t?
        HANDLE ntdll_handle = dil.hFile;
        if ( highdlls.add_high_module(addr, size, ntdll_handle) )
        {
          debdeb("%p: 64bit DLL loaded into high addresses has been detected\n",
                 addr);
          goto SILENTLY_RESUME;
        }

        // we defer the import of the dll until the moment when ida stops
        // at a debug event. we do so to avoid unnecessary imports because
        // the dll might get unloaded before ida stops.
        image_info_t di(this, DebugEvent.u.LoadDll, size, full_name);
        add_dll(di);
        // determine the attach breakpoint if needed
        size_t max_ntdlls = check_wow64_process() == WOW64_YES ? 2 : 1;
        if ( highdlls.count_ntdlls() < max_ntdlls )
        {
          if ( is_ntdll_name(full_name) )
            highdlls.add_ntdll(addr, size);
          if ( attach_status == as_none && !stop_at_ntdll_bpts )
            expecting_debug_break = highdlls.count_ntdlls();
        }
        break;
      }

SILENTLY_RESUME:
      // do not report this event to ida
      event->handled = true;
      dbg_continue_after_event(event);
      return GDE_NO_EVENT;

    case UNLOAD_DLL_DEBUG_EVENT:
      event->set_info(LIB_UNLOADED);
      {
        eanat_t addr = eanat_t(DebugEvent.u.UnloadDll.lpBaseOfDll);
        range_t range(addr, addr+MEMORY_PAGE_SIZE); // we assume DLL image is at least a PAGE size
        const char *name = get_range_name(dlls, &range);
        if ( name != NULL )
          event->info() = name;
        else
          event->info().clear();

        // remove ntdll from the list
        HANDLE ntdll_handle;
        if ( highdlls.del_high_module(&ntdll_handle, addr) )
        {
          myCloseHandle(ntdll_handle);
          goto SILENTLY_RESUME;
        }

        // close the associated DLL handle
        images_t::iterator p = dlls.find(addr);
        if ( p != dlls.end() )
        {
          myCloseHandle(p->second.dll_info.hFile);
          // Remove it from the list of dlls to import
          // (in the case it was never imported)
          dlls_to_import.erase(p->first);
          dlls.erase(p);
        }
        else
        {
          debdeb("Could not find dll to unload (base=%a)\n", EA_T(DebugEvent.u.UnloadDll.lpBaseOfDll));
        }
      }
      break;

    case OUTPUT_DEBUG_STRING_EVENT:
      {
        char buf[MAXSTR];
        get_debug_string(DebugEvent, buf, sizeof(buf));
        event->set_info(INFORMATION) = buf;
      }
      break;

    case RIP_EVENT:
      debdeb("RIP_EVENT (system debugging error)");
      break;

    default:
      debdeb("UNKNOWN_EVENT %d", DebugEvent.dwDebugEventCode);
      event->handled = false;      // don't handle it
      break;
  }

  if ( gdecode > GDE_NO_EVENT && attach_status == as_breakpoint && event->eid() == EXCEPTION )
  { // exception while attaching. apparently things went wrong
    // pretend that we attached successfully
    events.enqueue(*event, IN_BACK);
    create_attach_event(event, true);
    attach_status = as_none;
  }
  return gdecode;
}

//--------------------------------------------------------------------------
gdecode_t idaapi win32_debmod_t::dbg_get_debug_event(debug_event_t *event, int timeout_ms)
{
  check_thread(false);
  gdecode_t gdecode = get_debug_event(event, timeout_ms);
  if ( gdecode >= GDE_ONE_EVENT )
  {
    last_event = *event;
    in_event = &last_event;
    pause_requested = false;
  }
  return gdecode;
}


//--------------------------------------------------------------------------
bool win32_debmod_t::get_debug_string(const DEBUG_EVENT &ev, char *buf, size_t bufsize)
{
  buf[0] = '\0';
  size_t nullsize = ev.u.DebugString.fUnicode ? sizeof(wchar_t) : 1;
  size_t msize = qmin(ev.u.DebugString.nDebugStringLength, bufsize-nullsize);
  ea_t ea = EA_T(ev.u.DebugString.lpDebugStringData);
  ssize_t rsize = _read_memory(ea, buf, msize);
  if ( rsize == msize )
  {
    buf[rsize] = '\0';
    if ( ev.u.DebugString.fUnicode )
    {
      *(wchar_t*)(buf + rsize) = 0;
      utf16_to_utf8(buf, bufsize, (LPCWSTR)buf);
    }
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
void win32_debmod_t::cleanup()
{
  myCloseHandle(redirin_handle);
  myCloseHandle(redirout_handle);
  myCloseHandle(thread_handle);
  myCloseHandle(process_handle);
  myCloseHandle(cpdi.hFile);

  // Close handles of remaining DLLs
  for ( images_t::iterator p=dlls.begin(); p != dlls.end(); ++p )
    myCloseHandle(p->second.dll_info.hFile);

  pid = -1;
  highdlls.clear();
  stop_at_ntdll_bpts = qgetenv("IDA_SYSTEMBREAKPOINT");
  expecting_debug_break = 0;
  in_event = NULL;
  memset(&cpdi, 0, sizeof(cpdi));
  cpdi.hFile = INVALID_HANDLE_VALUE;
  cpdi.hProcess = INVALID_HANDLE_VALUE;
  cpdi.hThread = INVALID_HANDLE_VALUE;
  attach_status = as_none;
  attach_evid = INVALID_HANDLE_VALUE;

  old_ranges.clear();
  threads.clear();
  thread_bpts.clear();
  bpts.clear();
  curproc.clear();
  dlls.clear();
  dlls_to_import.clear();
  images.clear();
  thread_ranges.clear();
  class_ranges.clear();
  inherited::cleanup();
}

#define DRVBUFSIZE 512

//--------------------------------------------------------------------------
// Translate path with device name to drive letters.
// e.g. \Device\HarddiskVolume4\Windows\System32\ntdll.dll -> C:\Windows\System32\ntdll.dll
static void translate_nt_path(qstring *out, LPCWSTR pszFilename)
{
  WCHAR szTemp[DRVBUFSIZE];

  // get a list of all drive letters
  if ( GetLogicalDriveStringsW(qnumber(szTemp) - 1, szTemp) )
  {
    WCHAR szName[MAX_PATH];
    WCHAR szDrive[3] = L" :";
    BOOL bFound = FALSE;
    WCHAR *p = szTemp;

    do
    {
      // Copy the drive letter to the template string
      *szDrive = *p;

      // Look up device name for this drive
      DWORD uNameLen = QueryDosDeviceW(szDrive, szName, qnumber(szName) - 1);
      if ( uNameLen != 0 )
      {
        //for some reason return value is 2 chars longer, so get the actual length
        uNameLen = wcslen(szName);
        // do we have a match at the start of filename?
        bFound = _wcsnicmp(pszFilename, szName, uNameLen) == 0
              && pszFilename[uNameLen] == L'\\';

        if ( bFound )
        {
          // Reconstruct filename
          // by replacing device path with DOS path (drive)
          qstring path;
          utf16_utf8(out, szDrive);
          utf16_utf8(&path, pszFilename + uNameLen);
          out->append(path);
          return;
        }
      }

      // Go to the next NULL character.
      while ( *p++ )
        ;
    }
    while ( !bFound && *p ); // end of string
  }
}

//--------------------------------------------------------------------------
void win32_debmod_t::get_filename_for(
        char *buf,
        size_t bufsize,
        eanat_t image_name_ea,
        bool use_unicode,
        eanat_t image_base)
{
  buf[0] = '\0';
  // if we have address of file name in the process image from the debug API, try to use it
  //   remark: depending on the OS, NTDLL.DLL can return an empty string or only the DLL name!
  if ( image_name_ea != 0 )
    get_filename_from_process(image_name_ea, use_unicode, buf, bufsize);

  // various fallbacks
  // first try GetMappedFileName
  if ( buf[0] == '\0' && _GetMappedFileName != NULL )
  {
    wchar16_t tbuf[MAXSTR];
    HMODULE hmod = (HMODULE)(size_t)image_base;
    if ( _GetMappedFileName(process_handle, hmod, tbuf, qnumber(tbuf)) )
    {
      qstring tmp;
      translate_nt_path(&tmp, tbuf);
      qstrncpy(buf, tmp.c_str(), bufsize);
    }
  }

  // then try GetModuleFileNameEx
  if ( buf[0] == '\0' && _GetModuleFileNameEx != NULL )
  {
    wchar16_t tbuf[MAXSTR];
    HMODULE hmod = (HMODULE)(size_t)image_base;
    if ( _GetModuleFileNameEx(process_handle, hmod, tbuf, qnumber(tbuf)) )
    {
      qstring tmp;
      utf16_utf8(&tmp, tbuf);
      qstrncpy(buf, tmp.c_str(), bufsize);
    }
  }

  // last: we try to get DLL name by looking at the export name from
  //   the export directory in PE image in debugged process.
  // this is the least reliable way since this string may not match the actual dll filename
  if ( buf[0] == '\0' )
    get_pe_export_name_from_process(image_base, buf, bufsize);

  // if all these didn't work, then use toolhelp to get the module name
  // commented out: hangs under Windows ce
  /*
  if ( buf[0] == '\0' )
  {
  gmbb_info_t gi;
  gi.base    = image_base;
  gi.buf     = buf;
  gi.bufsize = bufsize;
  for_each_module(pid, get_module_by_base, &gi);
  }
  */

  // for dlls without path, try to find it
  find_full_path(buf, bufsize, process_path.c_str());

  // convert possible short path to long path
  qffblk64_t fb;
  if ( qfindfirst(buf, &fb, 0) == 0 )
  {
    char *fptr = qbasename(buf);
    qstrncpy(fptr, fb.ff_name, bufsize-(fptr-buf));
  }
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_detach_process()
{
  check_thread(false);
  if ( in_event != NULL )
    dbg_continue_after_event(in_event);
  BOOL ret = get_tool_help()->debug_detach_process(pid);
  if ( ret )
  {
    attach_status = as_detaching;
    exiting = true;
  }
  return ret ? DRC_OK : DRC_FAILED;
}

//--------------------------------------------------------------------------
void idaapi win32_debmod_t::dbg_set_debugging(bool _debug_debugger)
{
  debug_debugger = _debug_debugger;
}

//--------------------------------------------------------------------------
int idaapi win32_debmod_t::dbg_init(qstring * /*errbuf*/)
{
  check_thread(true);

  cleanup();
  cleanup_hwbpts();

  return g_code;
}

//--------------------------------------------------------------------------
image_info_t::image_info_t(win32_debmod_t *ses)
  : sess(ses), base(BADADDR), imagesize(0)
{
  memset(&dll_info, 0, sizeof(dll_info));
}

image_info_t::image_info_t(
        win32_debmod_t *ses,
        ea_t _base,
        uint32 _imagesize,
        const qstring &_name)
  : sess(ses), base(_base), imagesize(_imagesize), name(_name)
{
  memset(&dll_info, 0, sizeof(dll_info));
}

image_info_t::image_info_t(
        win32_debmod_t *ses,
        const LOAD_DLL_DEBUG_INFO &i,
        uint32 _imagesize,
        const char *_name)
  : sess(ses), name(_name), dll_info(i)
{
  base = EA_T(i.lpBaseOfDll);
  imagesize = _imagesize;
}

image_info_t::image_info_t(win32_debmod_t *ses, const modinfo_t &m)
  : sess(ses), base(m.base), imagesize(m.size), name(m.name)
{
  memset(&dll_info, 0, sizeof(dll_info));
}

//--------------------------------------------------------------------------
// get (path+)name from debugged process
// lpFileName - pointer to pointer to the file name
// use_unicode - true if the filename is in unicode
bool win32_debmod_t::get_filename_from_process(
        eanat_t name_ea,
        bool use_unicode,
        char *buf,
        size_t bufsize)
{
  buf[0] = '\0';
  if ( name_ea == 0 )
    return false;
  eanat_t dll_addr;
  if ( _read_memory(name_ea, &dll_addr, sizeof(dll_addr)) != sizeof(dll_addr) )
    return false;
  if ( dll_addr == NULL )
    return false;
  name_ea = dll_addr;
  if ( _read_memory(name_ea, buf, bufsize) != bufsize )
    return false;
  if ( use_unicode )
    utf16_to_utf8(buf, bufsize, (LPCWSTR)buf);
  return true;
}

//--------------------------------------------------------------------------
ea_t win32_debmod_t::get_region_info(ea_t ea, memory_info_t *mi)
{
  // okay to keep static, they won't change between clients
  static DWORD_PTR totalVirtual = 0;
  static DWORD granularity = 0;

  if ( totalVirtual == 0 )
  {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    granularity = si.dwAllocationGranularity;
    totalVirtual = (DWORD_PTR)si.lpMaximumApplicationAddress;
  }

  void *addr = (void *)(size_t)ea;
  MEMORY_BASIC_INFORMATION meminfo;
  while ( !VirtualQueryEx(process_handle,    // handle of process
                          addr,              // address of region
                          &meminfo,          // address of information buffer
                          sizeof(meminfo)) ) // size of buffer
  {
    // On Windows CE VirtualQueryEx can fail when called with addr == 0,
    // so try to call it again with the next page (and end loop after 2d
    // iteration to prevent scanning of huge number of pages)
    // It's possible VirtualQueryEx fails on Windows CE not only for zero
    // address: perhaps we shouldn't limit the number of iterations and return
    // to using of a separate variable 'first' (as in win32_debmod.cpp#34)
    if ( ea != 0 || ea >= totalVirtual )
      return BADADDR;
    // try to find next valid page
    ea += granularity;
    addr = (void *)(size_t)ea;
  }

  eanat_t startea = (eanat_t)meminfo.BaseAddress;
  eanat_t endea = startea + meminfo.RegionSize;
  if ( endea <= startea  //overflow/empty?
#if !defined(__X86__) && !defined(__EA64__)
    || endea >= BADADDR//crossed 4GB boundary
#endif
    )
  {
    if ( endea == startea )
    {
      // ignore empty sections ...
      mi->start_ea = BADADDR;
      mi->end_ea   = BADADDR;
      return endea + 1;
    }
    // signal end of enumeration
    endea = BADADDR;
  }

//  debdeb("VirtualQueryEx(%a): base = %a, end = %a, protect=0x%x, allocprotect=0x%x, state=0x%x\n", ea, startea, endea, meminfo.Protect, meminfo.AllocationProtect, meminfo.State);

  // hide the page bpts in this memory region from ida
  uint32 prot = meminfo.Protect;
  if ( mask_page_bpts(startea, endea, &prot) )
  {
    debdeb("   masked protect=0x%x\n", prot);
    meminfo.Protect = prot;
  }

  if ( (meminfo.State & (MEM_FREE|MEM_RESERVE)) == MEM_FREE // if the range isn't interesting for/accessible by IDA
    || (meminfo.Protect & PAGE_NOACCESS) != 0 )
  { // we simply return an invalid range, and a pointer to the next (eventual) range
    mi->start_ea = BADADDR;
    mi->end_ea   = BADADDR;
    return endea;
  }

  mi->start_ea = startea;
  mi->end_ea   = endea;
#ifdef __EA64__
  // we may be running a 32bit process in wow64 with ida64
  mi->bitness = check_wow64_process() > 0 ? 1 : 2;
#else
  mi->bitness = 1; // 32bit
#endif

  // convert Windows protection modes to IDA protection modes
  mi->perm = win_prot_to_ida_perm(meminfo.Protect);

  // try to associate a segment name to the memory range
  const char *ptr;
  if ( (ptr=get_range_name(curproc,       mi)) != NULL   // first try with the current process
    || (ptr=get_range_name(dlls,          mi)) != NULL   // then try in DLLs
    || (ptr=get_range_name(images,        mi)) != NULL   // then try in previous images ranges
    || (ptr=get_range_name(thread_ranges, mi)) != NULL ) // and finally in thread ranges
  {
    // return the filename without the file path
    mi->name = qbasename(ptr);
  }
  else
  {
    char buf[MAXSTR];
    buf[0] = '\0';
    //check for a mapped filename
    get_filename_for(buf, sizeof(buf), 0, false, mi->start_ea);
    if ( buf[0] != '\0' )
    {
      mi->name = qbasename(buf);
    }
    // if we found nothing, check if the segment is a PE file header, and we try to locate a name in it
    else if ( get_pe_export_name_from_process(mi->start_ea, buf, sizeof(buf)) )
    { // we insert it in the image ranges list
      uint32 size = calc_imagesize(mi->start_ea);
      image_info_t ii(this, mi->start_ea, size, buf);
      images.insert(std::make_pair(ii.base, ii));
      mi->name = buf;
    }
  }

  // try to associate a segment class name to the memory range
  mi->sclass = get_range_name(class_ranges, mi);
  return endea;
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_attach_process(pid_t _pid, int event_id, int /*flags*/, qstring * /*errbuf*/)
{
  check_thread(false);
  int addrsize = get_process_addrsize(_pid);
#ifndef __EA64__
  if ( addrsize > 4 )
  {
    dwarning("AUTOHIDE NONE\nPlease use ida64 to debug 64-bit applications");
    SetLastError(ERROR_NOT_SUPPORTED);
    return DRC_FAILED;
  }
#endif
  if ( !DebugActiveProcess(_pid) )
  {
    deberr("DebugActiveProcess %08lX", _pid);
    return DRC_FAILED;
  }
  debapp_attrs.addrsize = addrsize;
  attach_status = as_attaching;
  attach_evid = (HANDLE)(INT_PTR)(event_id);
  exiting = false;
  return DRC_OK;
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_start_process(
        const char *path,
        const char *args,
        const char *startdir,
        int flags,
        const char *input_path,
        uint32 input_file_crc32,
        qstring * /*errbuf*/)
{
  check_thread(false);
  // input file specified in the database does not exist
  if ( input_path[0] != '\0' && !qfileexist(input_path) )
  {
    dwarning("AUTOHIDE NONE\nInput file is missing: %s", input_path);
    return DRC_NOFILE;
  }

  input_file_path = input_path;
  is_dll = (flags & DBG_PROC_IS_DLL) != 0;

  char fullpath[QMAXPATH];
  if ( !qfileexist(path) )
  {
    if ( qisabspath(path) || !search_path(fullpath, sizeof(fullpath), path, false) )
    {
      dwarning("AUTOHIDE NONE\nCan not find application file '%s'", path);
      return DRC_NETERR;
    }
    path = fullpath;
  }

  drc_t mismatch = DRC_OK;
  if ( !check_input_file_crc32(input_file_crc32) )
    mismatch = DRC_CRC;

  exiting = false;

  // Build a full command line
  qstring args_buffer; // this vector must survive until create_process()
  if ( args != NULL && args[0] != '\0' )
  {
    args_buffer += '"';
    args_buffer += path;
    args_buffer += '"';
    args_buffer += ' ';
    args_buffer += args;
    args = args_buffer.c_str();
  }

  PROCESS_INFORMATION ProcessInformation;
  bool is_gui = (flags & DBG_PROC_IS_GUI) != 0;
  bool hide_window = (flags & DBG_HIDE_WINDOW) != 0;
  if ( !create_process(path, args, startdir, is_gui, hide_window, &ProcessInformation) )
    return DRC_FAILED;

  pid            = ProcessInformation.dwProcessId;
  process_handle = ProcessInformation.hProcess;
  thread_handle  = ProcessInformation.hThread;
  process_path   = path;

  debapp_attrs.addrsize = get_process_addrsize(pid);

  return mismatch;
}

//--------------------------------------------------------------------------
//lint -esym(1762,win32_debmod_t::myCloseHandle) could be made const
bool win32_debmod_t::myCloseHandle(HANDLE &h)
{
  bool ok = true;
  if ( h != INVALID_HANDLE_VALUE && h != NULL )
  {
    DWORD code;
    __try
    {
      ok = CloseHandle(h) != 0;
      if ( !ok )
        deberr("CloseHandle(%08X)", h);
    }
    __except ( code=GetExceptionCode() )
    {
      debdeb("CloseHandle(%08X) exception code %08X\n", h, code);
      ok = false;
    }
    h = INVALID_HANDLE_VALUE;
  }
  return ok;
}

//--------------------------------------------------------------------------
void win32_debmod_t::install_callgate_workaround(thread_info_t *ti, const debug_event_t *event)
{
  // add a breakpoint after the call statement
  ea_t bpt = event->ea + 7;
  ti->callgate_ea = bpt;
  if ( !set_thread_bpt(*ti, bpt) )
    INTERR(637); // how can it be?
}

//--------------------------------------------------------------------------
// we do not use 'firsttime' argument anymore. we could use it to distinguish
// the first chance and the second chance but it is more logical to
// behave consistently.
gdecode_t win32_debmod_t::handle_exception(
        debug_event_t *event,
        const EXCEPTION_RECORD &er,
        bool was_thread_bpt,
        bool /*firsttime*/)
{
  int code = er.ExceptionCode;
  const exception_info_t *ei = find_exception(code);

  eanat_t addr = eanat_t(er.ExceptionAddress);
  excinfo_t &exc = event->set_exception();
  event->ea = addr;
  exc.code = code;
  exc.can_cont = (er.ExceptionFlags == 0);
  exc.ea = BADADDR;
  event->handled = false;

  if ( exiting && ei == NULL )
  {
    event->set_exit_code(PROCESS_EXITED, -1);
    return GDE_ONE_EVENT;
  }

  bool suspend = true;

  // we don't expect callgate breakpoints anymore
  ea_t was_callgate_ea = BADADDR;
  thread_info_t *ti = threads.get(event->tid);
  if ( ti != NULL )
  {
    was_callgate_ea = ti->callgate_ea;
    ti->callgate_ea = BADADDR;
  }

  if ( ei != NULL )
  {
    event->handled = ei->handle();
    // if the user asked to suspend the process, do not resume
    if ( !was_thread_bpt )
      suspend = ei->break_on() || pause_requested;
  }
  if ( !suspend )
    suspend = should_suspend_at_exception(event, ei);
  exc.info.qclear();
  int elc_flags = 0;
  switch ( uint32(code) )
  {
    case EXCEPTION_BREAKPOINT:
    case STATUS_WX86_BREAKPOINT:
      if ( was_thread_bpt )
      {
        QASSERT(638, ti != NULL);

        // is installed the workaround for the 'freely running after syscall' problem?
        if ( was_callgate_ea == event->ea )
          event->set_eid(STEP);
        else
          event->set_eid(PROCESS_SUSPENDED);
        break;
      }
      if ( attach_status == as_breakpoint ) // the process was successfully suspended after an attachement
      {
        create_attach_event(event, true);
        break;
      }
      if ( expecting_debug_break > 0
        && highdlls.has(addr)
        && get_kernel_bpt_ea(event->ea, event->tid) == BADADDR ) // not user-defined bpt
      {
        --expecting_debug_break;
        debdeb("%a: resuming after DbgBreakPoint(), expecting bpts: %d\n", event->ea, expecting_debug_break);
        event->handled = true;
        dbg_continue_after_event(event);
        return GDE_NO_EVENT;
      }
      // is this a breakpoint set by ida?
      {
        ea_t kea = get_kernel_bpt_ea(event->ea, event->tid);
        if ( kea != BADADDR )
        {
          bptaddr_t &bpta = event->set_bpt();
          bpta.hea = BADADDR; // no referenced address (only for hardware breakpoint)
          bpta.kea = kea == event->ea ? BADADDR : kea;
          event->handled = true;
        }
      }
      break;
    case EXCEPTION_SINGLE_STEP:
    case STATUS_WX86_SINGLE_STEP:
      {
        bool is_stepping = ti != NULL && ti->is_tracing();
        // if this happened because of a hardware breakpoint
        // find out which one caused it
        if ( !check_for_hwbpt(event, is_stepping) )
        {
          // if we have not asked for single step, do not convert it to STEP
          if ( is_stepping )
          {
            event->set_eid(STEP);   // Single-step breakpoint
            event->handled = true;
            ti->clr_tracing();
            break;
          }
        }
      }
      break;
    case EXCEPTION_ACCESS_VIOLATION:
      {
        ea_t exc_ea = EA_T(er.ExceptionInformation[1]); // virtual address of the inaccessible data.
        exc.ea = exc_ea;
        // is this a page bpt?
        page_bpts_t::iterator p = find_page_bpt(exc_ea);
        if ( p == page_bpts.end() )
        {
          exc_ea = event->ea;
          p = find_page_bpt(exc_ea);
        }
        if ( p != page_bpts.end() )
        {
          // since on access violation the system does not update anything
          // there is no need to reset eip when handling lowcnd below.
          elc_flags |= ELC_KEEP_EIP;
          ea_t exc_eip = EA_T(er.ExceptionAddress);
          if ( !should_fire_page_bpt(p, exc_ea, er.ExceptionInformation[0],
                                     exc_eip, dep_policy) )
          { // Silently step over the page breakpoint
            if ( ti != NULL && ti->is_tracing() )
              elc_flags |= ELC_KEEP_SUSP;
            lowcnd_t lc;
            const pagebpt_data_t &bpt = p->second;
            lc.ea = bpt.ea;
            lc.type = bpt.type;
            lc.size = bpt.user_len;
            if ( !handling_lowcnds.has(bpt.ea)
              && handle_lowcnd(&lc, event, elc_flags) )
            {
              if ( (elc_flags & ELC_KEEP_SUSP) != 0 )
              { // if we were tracing, report a STEP event
                event->set_eid(STEP);
                event->handled = true;
                ti->clr_tracing();
                return GDE_ONE_EVENT;
              }
              return GDE_NO_EVENT;
            }
            // failed to step over, return the exception
          }
          else
          {
            bptaddr_t &bpta = event->set_bpt();
            bpta.hea = p->second.ea;
            bpta.kea = BADADDR;
            event->handled = true;
            break;
          }
        }
        if ( ei != NULL && event->eid() == EXCEPTION )
        {
          int einfo = er.ExceptionInformation[0];
          const char *verb = einfo == EXCEPTION_EXECUTE_FAULT ? "executed"
                           : einfo == EXCEPTION_WRITE_FAULT   ? "written"
                           :                                    "read";
          exc.info.sprnt(ei->desc.c_str(), event->ea, exc.ea, verb);
        }
      }
      break;
#define EXCEPTION_BCC_FATAL  0xEEFFACE
#define EXCEPTION_BCC_NORMAL 0xEEDFAE6
    case EXCEPTION_BCC_FATAL:
    case EXCEPTION_BCC_NORMAL:
      if ( er.NumberParameters == 5
        && er.ExceptionInformation[0] == 2 // these numbers are highly hypothetic
        && er.ExceptionInformation[1] == 3 )
      {
        EXCEPTION_RECORD r2;
        if ( dbg_read_memory(er.ExceptionInformation[3], &r2, sizeof(r2), NULL) == sizeof(r2) )
          return handle_exception(event, r2, false, false);
      }
      break;
#define MS_VC_EXCEPTION 0x406D1388L
    case MS_VC_EXCEPTION:
      // SetThreadName
      // https://msdn.microsoft.com/en-us/library/xcb2z8hs.aspx
      if ( er.ExceptionInformation[0] == 0x1000
        && er.ExceptionInformation[3] == 0x00 )
      {
        qstring name;
        name.resize(MAXSTR);
        ea_t nameaddr = er.ExceptionInformation[1];
        if ( dbg_read_memory(nameaddr, name.begin(), name.length(), NULL) > 0 )
        {
          thid_t tid = er.ExceptionInformation[2];
          msg("Thread %d is named '%s'\n", tid, name.c_str());
          thread_info_t *tin = threads.get(tid);
          if ( tin != NULL )
          {
            tin->name = name.c_str();
            tin->set_new_name();
          }
          event->handled = true;
        }
      }
      break;
  }
  if ( !pause_requested && evaluate_and_handle_lowcnd(event, elc_flags) )
    return GDE_NO_EVENT;

  if ( event->eid() == EXCEPTION )
  {
    if ( ei == NULL )
    {
      exc.info.sprnt("unknown exception code %X", code);
    }
    else if ( exc.info.empty() )
    {
      exc.info.sprnt(ei->desc.c_str(), event->ea,
                     ea_t(er.ExceptionInformation[0]),
                     ea_t(er.ExceptionInformation[1]));
    }
    if ( !suspend )
    {
      log_exception(event, ei);
      // if a single step was scheduled by the user
      if ( ti != NULL && ti->is_tracing() )
      {
        clear_tbit(*ti);
        if ( event->handled )
        {
          // since we mask the exception, we generate a STEP event
          event->set_eid(STEP);
          return GDE_ONE_EVENT; // got an event
        }
      }
      dbg_continue_after_event(event);
      return GDE_NO_EVENT;
    }
  }
  return GDE_ONE_EVENT;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::check_for_hwbpt(debug_event_t *event, bool is_stepping)
{
  ea_t ea = is_hwbpt_triggered(event->tid, is_stepping);
  if ( ea != BADADDR )
  {
    bptaddr_t &addr = event->set_bpt();
    addr.hea = ea;
    addr.kea = BADADDR;
    event->handled = true;
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
void win32_debmod_t::create_attach_event(debug_event_t *event, bool attached)
{
  event->set_modinfo(PROCESS_ATTACHED);
  event->handled = true;
  if ( attached )
    attach_status = as_attached;
  else
    attach_status = as_attaching;
  if ( attach_evid != INVALID_HANDLE_VALUE )
  {
    SetEvent(attach_evid);
    attach_evid = INVALID_HANDLE_VALUE;
  }
  modinfo_t &mi_ps = event->modinfo();
  get_debugged_module_info(&mi_ps);

  binary_to_import = mi_ps;
}

//--------------------------------------------------------------------------
void win32_debmod_t::create_start_event(debug_event_t *event)
{
  modinfo_t &mi_ps = event->set_modinfo(PROCESS_STARTED);
  ea_t base = EA_T(cpdi.lpBaseOfImage);

  process_snapshot_t psnap(get_tool_help());
  PROCESSENTRY32 pe32;
  for ( bool ok = psnap.first(TH32CS_SNAPNOHEAPS, &pe32); ok; ok = psnap.next(&pe32) )
  {
    if ( pe32.th32ProcessID == event->pid )
    {
      char exefile[QMAXPATH];
      tchar_utf8(exefile, pe32.szExeFile, sizeof(exefile));
      if ( !qisabspath(exefile) )
      {
        char abspath[QMAXPATH];
        get_filename_for(abspath,
                         sizeof(abspath),
                         /*image_name_ea=*/ 0,
                         /*use_unicode=*/ false, // irrelevant
                         base);
        if ( abspath[0] != '\0' )
          qstrncpy(exefile, abspath, sizeof(exefile));
      }
      if ( process_path.empty() || qisabspath(exefile) )
        process_path = exefile;
      break;
    }
  }
  mi_ps.name = process_path;
  mi_ps.base = base;
  mi_ps.size = calc_imagesize(base);
  mi_ps.rebase_to = BADADDR; // this must be determined locally - see common_local.cpp

  binary_to_import = mi_ps;
}

//--------------------------------------------------------------------------
ea_t win32_debmod_t::get_kernel_bpt_ea(ea_t ea, thid_t tid)
{
  if ( is_ida_bpt(ea, tid) )
    return ea;
  return BADADDR;
}


ssize_t idaapi win32_debmod_t::dbg_write_memory(ea_t ea, const void *buffer, size_t size, qstring * /*errbuf*/)
{
  check_thread(false);
  return _write_memory(ea, buffer, size, true);
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_thread_get_sreg_base(
        ea_t *pea,
        thid_t tid,
        int sreg_value,
        qstring * /*errbuf*/)
{
  check_thread(false);
  NODISTURB_ASSERT(in_event != NULL);
#ifdef __ARM__
  return DRC_FAILED;
#else //__ARM__
  HANDLE h = get_thread_handle(tid);
  if ( h == INVALID_HANDLE_VALUE )
    return DRC_FAILED;

#ifndef __X86__

  thread_info_t *ti = threads.get(tid);
  if ( ti != NULL && ti->read_context(X86_RC_SEGMENTS) )
  {
    // is this a TLS base register? (FS for wow64 and GS for x64)
    if ( sreg_value == ti->ctx.SegGs && ( ti->flags & THR_WOW64 ) == 0
      || sreg_value == ti->ctx.SegFs && ( ti->flags & THR_WOW64 ) != 0 )
    {
      // lpThreadLocalBase is the native (X64) TEB, or GS base
      if ( sreg_value == ti->ctx.SegGs )
        *pea = EA_T(ti->lpThreadLocalBase);
      else
      {
        // fs base is the WoW64 TEB
        // pointer to it is the first field in the native TEB
        LPVOID tib32;
        if ( _read_memory(EA_T(ti->lpThreadLocalBase), &tib32, sizeof(tib32)) != sizeof(tib32) )
          return DRC_FAILED;
        *pea = EA_T(tib32);
      }
      return DRC_OK;
    }
    else if ( (ti->flags & THR_WOW64) != 0 )
    {
      WOW64_LDT_ENTRY se;
      if ( !_Wow64GetThreadSelectorEntry(h, sreg_value, &se) )
      {
        if ( GetLastError() == ERROR_NOT_SUPPORTED )
        {
          // in x64 all selectors except fs/gs are 0-based
          *pea = 0;
          return DRC_OK;
        }
        deberr("GetThreadSelectorEntry");
        return DRC_FAILED;
      }
     *pea = (se.HighWord.Bytes.BaseHi << 24)
          | (se.HighWord.Bytes.BaseMid << 16)
          | se.BaseLow;
     return DRC_OK;
    }
  }
#endif  // __X64__
  //below code works for non-x64
  LDT_ENTRY se;
  if ( !GetThreadSelectorEntry(h, sreg_value, &se) )
  {
    if ( GetLastError() == ERROR_NOT_SUPPORTED )
    {
      *pea = 0;
      return DRC_OK;
    }
    deberr("GetThreadSelectorEntry");
    return DRC_FAILED;
  }

  *pea = (se.HighWord.Bytes.BaseHi << 24)
       | (se.HighWord.Bytes.BaseMid << 16)
       | se.BaseLow;
  return DRC_OK;
#endif  // __ARM__
}

//--------------------------------------------------------------------------
#ifndef __X86__
#define FloatSave FltSave       // FIXME: use XMM save area!
#define RegisterArea FloatRegisters
#define FPUREG_ENTRY_SIZE  16
#define XMMREG_PTR   ((uchar *)&ctx.Xmm0)
#define XMMREG_MXCSR (ctx.FltSave.MxCsr)
#else
#define XMMREG_PTR ((uchar *)&ctx.ExtendedRegisters[0xA0])
#define XMMREG_MXCSR (*(uint32 *)&ctx.ExtendedRegisters[0x18])
#define FPUREG_ENTRY_SIZE  10
#endif

#define FPUREG_PTR        ((uchar *)ctx.FloatSave.RegisterArea)

drc_t idaapi win32_debmod_t::dbg_write_register(
        thid_t tid,
        int reg_idx,
        const regval_t *value,
        qstring * /*errbuf*/)
{
  check_thread(false);
  if ( value == NULL )
    return DRC_FAILED;

  NODISTURB_ASSERT(in_event != NULL);

  int regclass = get_reg_class(reg_idx);
  if ( regclass == 0 )
    return DRC_FAILED;

  thread_info_t *ti = threads.get(tid);
  if ( ti == NULL || !ti->read_context(regclass) )
    return DRC_FAILED;
  CONTEXT &ctx = ti->ctx;

  // Patch one field
  patch_context_struct(ctx, reg_idx, value);

  bool ok = ti->write_context(regclass);
  if ( !ok )
    deberr("SetThreadContext");
  debdeb("write_register: %d\n", ok);
  return ok ? DRC_OK : DRC_FAILED;
}

//--------------------------------------------------------------------------
bool idaapi win32_debmod_t::write_registers(
        thid_t thread_id,
        int start,
        int count,
        const regval_t *values,
        const int *indices)
{
  thread_info_t *ti = threads.get(thread_id);
  if ( ti == NULL )
    return false;
  if ( !ti->read_context(RC_ALL) )
    return false;

  for ( int i=0; i < count; i++, values++ )
  {
    int idx = indices != NULL ? indices[i] : start+i;
    patch_context_struct(ti->ctx, idx, values);
  }

  bool ok = ti->write_context(RC_ALL);
  if ( !ok )
    deberr("SetThreadContext");
  debdeb("write_registers: %d\n", ok);
  return ok;
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_read_registers(
        thid_t tid,
        int clsmask,
        regval_t *values,
        qstring * /*errbuf*/)
{
  check_thread(false);
  if ( values == NULL )
    return DRC_FAILED;

  NODISTURB_ASSERT(in_event != NULL);

  thread_info_t *ti = threads.get(tid);
  if ( ti == NULL || !ti->read_context(clsmask) )
    return DRC_FAILED;

  CONTEXT &ctx = ti->ctx;
#ifdef __ARM__
  if ( (clsmask & ARM_RC_GENERAL) != 0 )
  {
    values[R_R0 ].ival    = ctx.R0;
    values[R_R1 ].ival    = ctx.R1;
    values[R_R2 ].ival    = ctx.R2;
    values[R_R3 ].ival    = ctx.R3;
    values[R_R4 ].ival    = ctx.R4;
    values[R_R5 ].ival    = ctx.R5;
    values[R_R6 ].ival    = ctx.R6;
    values[R_R7 ].ival    = ctx.R7;
    values[R_R8 ].ival    = ctx.R8;
    values[R_R9 ].ival    = ctx.R9;
    values[R_R10].ival    = ctx.R10;
    values[R_R11].ival    = ctx.R11;
    values[R_R12].ival    = ctx.R12;
    values[R_SP ].ival    = ctx.Sp;
    values[R_LR ].ival    = ctx.Lr;
    values[R_PC ].ival    = ctx.Pc;
    values[R_PSR].ival    = ctx.Psr;
  }
#else
  if ( (clsmask & X86_RC_SEGMENTS) != 0 )
  {
    values[R_CS].ival     = ctx.SegCs;
    values[R_DS].ival     = ctx.SegDs;
    values[R_ES].ival     = ctx.SegEs;
    values[R_FS].ival     = ctx.SegFs;
    values[R_GS].ival     = ctx.SegGs;
    values[R_SS].ival     = ctx.SegSs;
  }
  if ( (clsmask & X86_RC_GENERAL) != 0 )
  {
#ifndef __X86__
    values[R_EAX].ival    = ctx.Rax;
    values[R_EBX].ival    = ctx.Rbx;
    values[R_ECX].ival    = ctx.Rcx;
    values[R_EDX].ival    = ctx.Rdx;
    values[R_ESI].ival    = ctx.Rsi;
    values[R_EDI].ival    = ctx.Rdi;
    values[R_EBP].ival    = ctx.Rbp;
    values[R_ESP].ival    = ctx.Rsp;
    values[R_EIP].ival    = ctx.Rip;
#  ifdef __EA64__
    values[R64_R8 ].ival  = ctx.R8;
    values[R64_R9 ].ival  = ctx.R9;
    values[R64_R10].ival  = ctx.R10;
    values[R64_R11].ival  = ctx.R11;
    values[R64_R12].ival  = ctx.R12;
    values[R64_R13].ival  = ctx.R13;
    values[R64_R14].ival  = ctx.R14;
    values[R64_R15].ival  = ctx.R15;
#  endif
#else
    values[R_EAX].ival    = ctx.Eax;
    values[R_EBX].ival    = ctx.Ebx;
    values[R_ECX].ival    = ctx.Ecx;
    values[R_EDX].ival    = ctx.Edx;
    values[R_ESI].ival    = ctx.Esi;
    values[R_EDI].ival    = ctx.Edi;
    values[R_EBP].ival    = ctx.Ebp;
    values[R_ESP].ival    = ctx.Esp;
    values[R_EIP].ival    = ctx.Eip;
#endif
    values[R_EFLAGS].ival = ctx.EFlags;
  }
  if ( (clsmask & (X86_RC_FPU|X86_RC_MMX)) != 0 )
  {
    if ( (clsmask & X86_RC_FPU) != 0 )
    {
      values[R_CTRL].ival = ctx.FloatSave.ControlWord;
      values[R_STAT].ival = ctx.FloatSave.StatusWord;
      values[R_TAGS].ival = ctx.FloatSave.TagWord;
    }
    read_fpu_registers(values, clsmask, FPUREG_PTR, FPUREG_ENTRY_SIZE);
  }
  if ( (clsmask & X86_RC_XMM) != 0 )
  {
    const uchar *xptr = XMMREG_PTR;
    for ( int i=R_XMM0; i < R_MXCSR; i++,xptr+=16 )
      values[i].set_bytes(xptr, 16);
    values[R_MXCSR].ival = XMMREG_MXCSR;
  }
  //? others registers
#endif

  return DRC_OK;
}

//--------------------------------------------------------------------------
#ifndef __ARM__
bool thread_info_t::toggle_tbit(bool set_tbit, win32_debmod_t *debmod)
{
  if ( !read_context(RC_GENERAL) )
    return false;

  bool ok = true;
  CASSERT(EFLAGS_TRAP_FLAG == 0x100); // so we can shift set_tbit << 8
  if ( (ctx.EFlags & EFLAGS_TRAP_FLAG) != (set_tbit << 8) )   //lint !e647 possible truncation before conversion from 'int' to 'unsigned long'
  {
    QASSERT(30117, (ctx.ContextFlags & CONTEXT_CONTROL) != 0);
    ctx.EFlags |= EFLAGS_TRAP_FLAG;
    int saved = ctx.ContextFlags;
    ctx.ContextFlags = CONTEXT_CONTROL;
    ok = write_context(RC_GENERAL);
    ctx.ContextFlags = saved;
    if ( ok )
      setflag(flags, THR_TRACING, set_tbit);
    else
      debmod->deberr("%d: SetThreadContext failed", tid);
  }
  return ok;
}
#endif

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_set_resume_mode(thid_t tid, resume_mode_t resmod)
{
  if ( resmod != RESMOD_INTO )
    return DRC_FAILED; // not supported

  check_thread(false);
  NODISTURB_ASSERT(in_event != NULL);
#ifdef __ARM__
  return DRC_FAILED;
#else
  thread_info_t *ti = threads.get(tid);
  if ( ti == NULL )
    return DRC_FAILED;

  bool ok = ti->toggle_tbit(true, this);
  if ( !ok )
    deberr("%d: (set_step) SetThreadContext failed", tid);
  return ok ? DRC_OK : DRC_FAILED;
#endif
}

//--------------------------------------------------------------------------
bool win32_debmod_t::clear_tbit(thread_info_t &ti)
{
  NODISTURB_ASSERT(in_event != NULL);
#ifdef __ARM__
  return false;
#else
  bool ok = ti.toggle_tbit(false, this);
  if ( !ok )
    deberr("%d: (clr_step) SetThreadContext failed", ti.tid);
  return ok;
#endif
}

//--------------------------------------------------------------------------
// invalidate registers of all threads
void win32_debmod_t::invalidate_all_contexts(void)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    p->second.invalidate_context();
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_continue_after_event(const debug_event_t *event)
{
  check_thread(false);
  NODISTURB_ASSERT(in_event != NULL || exiting);

  if ( event == NULL )
    return DRC_FAILED;

  if ( events.empty() )
  {
    bool done = false;
    if ( !done )    //-V547 '!done' is always true
    {
      // check if we need to install the workaround for single stepping over callgates
      thread_info_t *ti = threads.get(event->tid);
      if ( ti != NULL && ti->is_tracing() )
      {
        if ( check_for_call_large(event, process_handle) )
          install_callgate_workaround(ti, event);
      }

      int flag = event->handled ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED;
      if ( !ContinueDebugEvent(event->pid, event->tid, flag) )
      {
        deberr("ContinueDebugEvent");
        return DRC_FAILED;
      }
      debdeb("ContinueDebugEvent: handled=%s\n", event->handled ? "yes" : "no");
      if ( event->eid() == PROCESS_EXITED )
      {
        // from WaitForDebugEvent help page:
        //  If the system previously reported an EXIT_PROCESS_DEBUG_EVENT debugging event,
        //  the system closes the handles to the process and thread when the debugger calls the ContinueDebugEvent function.
        // => we don't close these handles to avoid error messages
        cpdi.hProcess = INVALID_HANDLE_VALUE;
        cpdi.hThread  = INVALID_HANDLE_VALUE;
        process_handle= INVALID_HANDLE_VALUE;
        thread_handle = INVALID_HANDLE_VALUE;
        cleanup();
      }
    }
    invalidate_all_contexts();
  }
  in_event = NULL;
  return DRC_OK;
}

//--------------------------------------------------------------------------
drc_t idaapi win32_debmod_t::dbg_exit_process(qstring * /*errbuf*/)
{
  check_thread(false);
  // WindowsCE sometimes reports failure but terminates the application.
  // We ignore the return value.
  bool check_termination_code = prepare_to_stop_process(in_event, threads);
  bool terminated = TerminateProcess(process_handle, -1) != 0;
  if ( !terminated && check_termination_code )
  {
    deberr("TerminateProcess");
    return DRC_FAILED;
  }
  exiting = true;

  if ( in_event != NULL && dbg_continue_after_event(in_event) != DRC_OK )
  {
    deberr("continue_after_event");
    return DRC_FAILED;
  }
  return DRC_OK;
}


//--------------------------------------------------------------------------
void win32_debmod_t::show_exception_record(const EXCEPTION_RECORD &er, int level)
{
  char name[MAXSTR];
  get_exception_name(er.ExceptionCode, name, sizeof(name));
  if ( level > 0 )
    dmsg("%*c", level, ' ');
  dmsg("%s: fl=%X adr=%a #prm=%d\n",
    name,
    er.ExceptionFlags,
    EA_T(er.ExceptionAddress),
    er.NumberParameters);
  if ( er.NumberParameters > 0 )
  {
    dmsg("%*c", level+2, ' ');
    int n = qmin(er.NumberParameters, EXCEPTION_MAXIMUM_PARAMETERS);
    for ( int i=0; i < n; i++ )
      dmsg("%s0x%a", i == 0 ? "" : " ", ea_t(er.ExceptionInformation[i]));
    dmsg("\n");
  }
  if ( er.ExceptionRecord != NULL )
    show_exception_record(*er.ExceptionRecord, level+2);
}

//--------------------------------------------------------------------------
void win32_debmod_t::show_debug_event(const DEBUG_EVENT &ev)
{
  if ( !debug_debugger )
    return;
  dmsg("[%u %d] ", ev.dwProcessId, ev.dwThreadId);
  switch ( ev.dwDebugEventCode )
  {
    case EXCEPTION_DEBUG_EVENT:
      {
        const EXCEPTION_RECORD &er = ev.u.Exception.ExceptionRecord;
        dmsg("EXCEPTION: ea=%p first: %d ",
          er.ExceptionAddress, ev.u.Exception.dwFirstChance);
        show_exception_record(er);
      }
      break;

    case CREATE_THREAD_DEBUG_EVENT:
      dmsg("CREATE_THREAD: hThread=%X LocalBase=%p Entry=%p\n",
        ev.u.CreateThread.hThread,
        ev.u.CreateThread.lpThreadLocalBase,
        ev.u.CreateThread.lpStartAddress);
      break;

    case CREATE_PROCESS_DEBUG_EVENT:
      {
        const CREATE_PROCESS_DEBUG_INFO &cpinf = ev.u.CreateProcessInfo;
        char path[QMAXPATH];
        if ( process_handle == INVALID_HANDLE_VALUE )
          process_handle = cpinf.hProcess;
        get_filename_for(
          path,
          sizeof(path),
          eanat_t(cpinf.lpImageName),
          cpinf.fUnicode != 0,
          eanat_t(cpinf.lpBaseOfImage));
        dmsg("CREATE_PROCESS: hFile=%X hProcess=%X hThread=%X "
          "base=%p\n dbgoff=%X dbgsiz=%X tlbase=%p start=%p name=%p '%s' \n",
          cpinf.hFile, cpinf.hProcess, cpinf.hThread, cpinf.lpBaseOfImage,
          cpinf.dwDebugInfoFileOffset, cpinf.nDebugInfoSize, cpinf.lpThreadLocalBase,
          cpinf.lpStartAddress, cpinf.lpImageName, path);
      }
      break;

    case EXIT_THREAD_DEBUG_EVENT:
      dmsg("EXIT_THREAD: code=%d\n", ev.u.ExitThread.dwExitCode);
      break;

    case EXIT_PROCESS_DEBUG_EVENT:
      dmsg("EXIT_PROCESS: code=%d\n", ev.u.ExitProcess.dwExitCode);
      break;

    case LOAD_DLL_DEBUG_EVENT:
      {
        char path[QMAXPATH];
        const LOAD_DLL_DEBUG_INFO &di = ev.u.LoadDll;
        get_filename_for(
          path,
          sizeof(path),
          eanat_t(di.lpImageName),
          di.fUnicode != 0,
          eanat_t(di.lpBaseOfDll));
        dmsg("LOAD_DLL: h=%X base=%p dbgoff=%X dbgsiz=%X name=%X '%s'\n",
          di.hFile, di.lpBaseOfDll, di.dwDebugInfoFileOffset, di.nDebugInfoSize,
          di.lpImageName, path);
      }
      break;

    case UNLOAD_DLL_DEBUG_EVENT:
      dmsg("UNLOAD_DLL: base=%p\n", ev.u.UnloadDll.lpBaseOfDll);
      break;

    case OUTPUT_DEBUG_STRING_EVENT:
      {
        char buf[MAXSTR];
        get_debug_string(ev, buf, sizeof(buf));
        dmsg("OUTPUT_DEBUG_STRING: str=\"%s\"\n", buf);
      }
      break;

    case RIP_EVENT:
      dmsg("RIP_EVENT (system debugging error)\n");
      break;

    default:
      dmsg("UNKNOWN_DEBUG_EVENT %d\n", ev.dwDebugEventCode);
      break;
  }
}

//--------------------------------------------------------------------------
void win32_debmod_t::patch_context_struct(
        CONTEXT &ctx,
        int reg_idx,
        const regval_t *value) const
{
#ifdef __ARM__
  switch ( reg_idx )
  {
    case R_R0:  ctx.R0  = value->ival; break;
    case R_R1:  ctx.R1  = value->ival; break;
    case R_R2:  ctx.R2  = value->ival; break;
    case R_R3:  ctx.R3  = value->ival; break;
    case R_R4:  ctx.R4  = value->ival; break;
    case R_R5:  ctx.R5  = value->ival; break;
    case R_R6:  ctx.R6  = value->ival; break;
    case R_R7:  ctx.R7  = value->ival; break;
    case R_R8:  ctx.R8  = value->ival; break;
    case R_R9:  ctx.R9  = value->ival; break;
    case R_R10: ctx.R10 = value->ival; break;
    case R_R11: ctx.R11 = value->ival; break;
    case R_R12: ctx.R12 = value->ival; break;
    case R_SP:  ctx.Sp  = value->ival; break;
    case R_LR:  ctx.Lr  = value->ival; break;
    case R_PC:  ctx.Pc  = value->ival; break;
    case R_PSR: ctx.Psr = value->ival; break;
  }
#else
  switch ( reg_idx )
  {
    case R_CS:     ctx.SegCs                 = WORD(value->ival); break;
    case R_DS:     ctx.SegDs                 = WORD(value->ival); break;
    case R_ES:     ctx.SegEs                 = WORD(value->ival); break;
    case R_FS:     ctx.SegFs                 = WORD(value->ival); break;
    case R_GS:     ctx.SegGs                 = WORD(value->ival); break;
    case R_SS:     ctx.SegSs                 = WORD(value->ival); break;
#ifndef __X86__
    case R_EAX:    ctx.Rax                   = value->ival; break;
    case R_EBX:    ctx.Rbx                   = value->ival; break;
    case R_ECX:    ctx.Rcx                   = value->ival; break;
    case R_EDX:    ctx.Rdx                   = value->ival; break;
    case R_ESI:    ctx.Rsi                   = value->ival; break;
    case R_EDI:    ctx.Rdi                   = value->ival; break;
    case R_EBP:    ctx.Rbp                   = value->ival; break;
    case R_ESP:    ctx.Rsp                   = value->ival; break;
    case R_EIP:    ctx.Rip                   = value->ival; break;
#  ifdef __EA64__
    case R64_R8:   ctx.R8                    = value->ival; break;
    case R64_R9 :  ctx.R9                    = value->ival; break;
    case R64_R10:  ctx.R10                   = value->ival; break;
    case R64_R11:  ctx.R11                   = value->ival; break;
    case R64_R12:  ctx.R12                   = value->ival; break;
    case R64_R13:  ctx.R13                   = value->ival; break;
    case R64_R14:  ctx.R14                   = value->ival; break;
    case R64_R15:  ctx.R15                   = value->ival; break;
#  endif
#else
    case R_EAX:    ctx.Eax                   = (size_t)value->ival; break;
    case R_EBX:    ctx.Ebx                   = (size_t)value->ival; break;
    case R_ECX:    ctx.Ecx                   = (size_t)value->ival; break;
    case R_EDX:    ctx.Edx                   = (size_t)value->ival; break;
    case R_ESI:    ctx.Esi                   = (size_t)value->ival; break;
    case R_EDI:    ctx.Edi                   = (size_t)value->ival; break;
    case R_EBP:    ctx.Ebp                   = (size_t)value->ival; break;
    case R_ESP:    ctx.Esp                   = (size_t)value->ival; break;
    case R_EIP:    ctx.Eip                   = (size_t)value->ival; break;
#ifdef __EA64__
    case R64_R8:   break;
    case R64_R9 :  break;
    case R64_R10:  break;
    case R64_R11:  break;
    case R64_R12:  break;
    case R64_R13:  break;
    case R64_R14:  break;
    case R64_R15:  break;
#endif
#endif
    case R_TAGS:   ctx.FloatSave.TagWord     = WORD(value->ival); break;
    case R_EFLAGS: ctx.EFlags                = DWORD(value->ival); break;
    case R_CTRL:   ctx.FloatSave.ControlWord = WORD(value->ival); break;
    case R_STAT:   ctx.FloatSave.StatusWord  = WORD(value->ival); break;
    case R_MXCSR:  XMMREG_MXCSR              = value->ival; break;
    default:
      {
        void *xptr = NULL;
        int nbytes = 0;
        int regclass = get_reg_class(reg_idx);
        if ( (regclass & X86_RC_XMM) != 0 )
        { // XMM registers
          xptr = XMMREG_PTR + (reg_idx - R_XMM0) * 16;
          nbytes = 16;
        }
        else if ( (regclass & X86_RC_FPU) != 0 )
        {
          xptr = FPUREG_PTR + (reg_idx-R_ST0) * FPUREG_ENTRY_SIZE;
          nbytes = 10;
        }
        else if ( (regclass & X86_RC_MMX) != 0 )
        {
          xptr = FPUREG_PTR + (reg_idx-R_MMX0) * FPUREG_ENTRY_SIZE;
          nbytes = 8;
        }
        else
        {
          INTERR(30118);
        }
        const void *vptr = value->get_data();
        size_t size = value->get_data_size();
        memcpy(xptr, vptr, qmin(size, nbytes));   //-V575 null pointer 'xptr'
      }
      break;
   }
#endif
}

//--------------------------------------------------------------------------
int win32_debmod_t::dbg_freeze_threads_except(thid_t tid)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    if ( p->first != tid )
      _sure_suspend_thread(p->second, true);
  return 1;
}

//--------------------------------------------------------------------------
int win32_debmod_t::dbg_thaw_threads_except(thid_t tid)
{
  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
    if ( p->first != tid )
      _sure_resume_thread(p->second, true);
  return 1;
}

//--------------------------------------------------------------------------
// if we have to do something as soon as we noticed the connection
// broke, this is the correct place
bool idaapi win32_debmod_t::dbg_prepare_broken_connection(void)
{
  broken_connection = true;
  bool ret = false;
  if ( restore_broken_breakpoints() )
  {
    // create the required event for synchronization; we use it
    // to notify when the process was successfully detached
    broken_event_handle = CreateEvent(NULL, false, false, NULL);

    if ( broken_event_handle != NULL )
    {
      int code = WAIT_TIMEOUT;
      while ( code == WAIT_TIMEOUT )
        code = WaitForSingleObject(broken_event_handle, 100);

      if ( code == WAIT_OBJECT_0 )
      {
        suspend_running_threads(_suspended_threads);
        if ( dbg_detach_process() == DRC_OK )
          SetEvent(broken_event_handle);
      }
    }
  }

  return ret;
}

//--------------------------------------------------------------------------
// Continuing from a broken connection in win32 debugger consist in the
// following step (if we're talking about a single threaded server):
//
//  1 - Notify the other thread that we want to reuse that connection
//  2 - Wait for the previous thread to notify that finished his work
//  3 - Reattach to the process and reopen thread's handles as, for a
//      reason, the handles we have are invalid (why?).
//  4 - Resume the threads we suspended before.
//
bool idaapi win32_debmod_t::dbg_continue_broken_connection(pid_t _pid)
{
  debmod_t::dbg_continue_broken_connection(_pid);

  QASSERT(676, broken_event_handle != NULL);

  // notify the broken thread we want to reuse the connection
  SetEvent(broken_event_handle);

  // and wait for the notification for a maximum of 15 seconds
  // as we don't want to wait forever (INFINITE) because the
  // other thread may fail
  int code = WaitForSingleObject(broken_event_handle, 15000);
  if ( code != WAIT_OBJECT_0 )
  {
    msg("Error restoring broken connection");
    return false;
  }

  if ( dbg_attach_process(_pid, -1, 0, NULL) == DRC_OK && reopen_threads() )
  {
    resume_suspended_threads(_suspended_threads);
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
bool win32_debmod_t::reopen_threads(void)
{
  if ( _OpenThread == NULL )
    return false;

  for ( threads_t::iterator p=threads.begin(); p != threads.end(); ++p )
  {
    HANDLE hThread;
    hThread = _OpenThread(THREAD_ALL_ACCESS, true, p->second.tid);
    if ( hThread != NULL )
      p->second.hThread = hThread;
    else
      deberr("OpenThread");
    p->second.suspend_count = get_thread_suspend_count(hThread);
  }
  return true;
}

//--------------------------------------------------------------------------
static bool enable_privilege(LPCTSTR privilege, bool enable);
static bool g_subsys_inited = false;
static bool g_got_debpriv = false;

bool init_subsystem()
{
  if ( g_subsys_inited )
    return true;

  if ( !win32_debmod_t::winver.ok() )
    return false;

  win_tool_help_t *wth = win32_debmod_t::get_tool_help();
  if ( wth->ok() )
    g_code |= DBG_HAS_GET_PROCESSES;

  // DebugActiveProcessStop() is only available on XP/2K3
  if ( wth->use_debug_detach_process() )
    g_code |= DBG_HAS_DETACH_PROCESS;

  g_got_debpriv = enable_privilege(SE_DEBUG_NAME, true);
  if ( !g_got_debpriv )
    msg("Can not set debug privilege: %s.\n"
        "Debugging of processes owned by another account won't be possible.\n",
        winerr(GetLastError()));

  win32_debmod_t::reuse_broken_connections = true;
  init_win32_subsystem();

  HINSTANCE h = GetModuleHandle(kernel32_dll);
  *(FARPROC*)&_OpenThread = GetProcAddress(h, TEXT("OpenThread"));
  *(FARPROC*)&_GetThreadDescription = GetProcAddress(h, TEXT("GetThreadDescription"));

#ifndef __X86__
  *(FARPROC*)&_Wow64GetThreadContext = GetProcAddress(h, TEXT("Wow64GetThreadContext"));
  *(FARPROC*)&_Wow64SetThreadContext = GetProcAddress(h, TEXT("Wow64SetThreadContext"));
  *(FARPROC*)&_Wow64GetThreadSelectorEntry = GetProcAddress(h, TEXT("Wow64GetThreadSelectorEntry"));
#endif

  g_subsys_inited = g_code != 0;
  return g_subsys_inited;
}

//--------------------------------------------------------------------------
bool term_subsystem()
{
  if ( !g_subsys_inited )
    return true;

  g_subsys_inited = false;

  if ( g_got_debpriv )
  {
    enable_privilege(SE_DEBUG_NAME, false);
    g_got_debpriv = false;
  }

  term_win32_subsystem();
  return true;
}

//--------------------------------------------------------------------------
debmod_t *create_debug_session()
{
  return new win32_debmod_t();
}

//--------------------------------------------------------------------------
//
//      DEBUG PRIVILEGE
//
//--------------------------------------------------------------------------
// dynamic linking information for Advapi functions
static HMODULE hAdvapi32 = NULL;
// function prototypes
typedef BOOL (WINAPI *OpenProcessToken_t)(
        HANDLE ProcessHandle,
        DWORD DesiredAccess,
        PHANDLE TokenHandle);
typedef BOOL (WINAPI *LookupPrivilegeValue_t)(
        LPCTSTR lpSystemName,
        LPCTSTR lpName,
        PLUID lpLuid);
typedef BOOL (WINAPI *AdjustTokenPrivileges_t)(
        HANDLE TokenHandle,
        BOOL DisableAllPrivileges,
        PTOKEN_PRIVILEGES NewState,
        DWORD BufferLength,
        PTOKEN_PRIVILEGES PreviousState,
        PDWORD ReturnLength);

// Function pointers
static OpenProcessToken_t      _OpenProcessToken      = NULL;
static LookupPrivilegeValue_t  _LookupPrivilegeValue  = NULL;
static AdjustTokenPrivileges_t _AdjustTokenPrivileges = NULL;

//--------------------------------------------------------------------------
static void term_advapi32(void)
{
  if ( hAdvapi32 != NULL )
  {
    DWORD code = GetLastError();
    FreeLibrary(hAdvapi32);
    SetLastError(code);
    hAdvapi32 = NULL;
  }
}

//--------------------------------------------------------------------------
static bool init_advapi32(void)
{
  // load the library
  hAdvapi32 = LoadLibrary(TEXT("advapi32.dll"));
  if ( hAdvapi32 == NULL )
    return false;

  // find the needed functions
  *(FARPROC*)&_OpenProcessToken       = GetProcAddress(hAdvapi32, TEXT("OpenProcessToken"));
  *(FARPROC*)&_LookupPrivilegeValue   = GetProcAddress(hAdvapi32, TEXT(LookupPrivilegeValue_Name));
  *(FARPROC*)&_AdjustTokenPrivileges  = GetProcAddress(hAdvapi32, TEXT("AdjustTokenPrivileges"));

  bool ok = _OpenProcessToken      != NULL
         && _LookupPrivilegeValue  != NULL
         && _AdjustTokenPrivileges != NULL;
  if ( !ok )
    term_advapi32();
  return ok;
}


//--------------------------------------------------------------------------
// based on code from:
// http://support.microsoft.com/support/kb/articles/Q131/0/65.asp
static bool enable_privilege(LPCTSTR privilege, bool enable)
{
  if ( !win32_debmod_t::winver.is_NT() ) // no privileges on 9X/ME
    return true;

  bool ok = false;
  if ( init_advapi32() )
  {
    HANDLE hToken;
    DWORD tokens = TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY;
    if ( _OpenProcessToken(GetCurrentProcess(), tokens, &hToken) )
    {
      LUID luid;
      if ( _LookupPrivilegeValue(NULL, privilege, &luid) )
      {
        TOKEN_PRIVILEGES tp;
        memset(&tp, 0, sizeof(tp));
        tp.PrivilegeCount           = 1;
        tp.Privileges[0].Luid       = luid;
        tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
        ok = _AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL) != FALSE;
      }
      CloseHandle(hToken);
    }
    term_advapi32();
  }
  return ok;
}
