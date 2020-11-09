import idaapi
import idc
import idautils
from idc import FUNCATTR_START

def xrefs_log_func(logFun):
    funcs_list = []
    for xref in idautils.XrefsTo(logFun,0):
        funcs_list.append(xref.frm)
    
    return funcs_list

def rename_func_by_handle(startAddr,endAddr,offset1 = 8, offset2=4):
    # offset1 -> handle string -> get new func name
    # offset2 -> handle func   -> get func addr
    for addr in range(startAddr,endAddr,offset1):
        for xref in idautils.XrefsFrom(addr,0):
            name = idc.get_strlit_contents(xref.to)
            print('[INFO]{}'.format(name))
            for xref in idautils.XrefsFrom(addr+offset2,0):
                func_addr = xref.to
                # name = name.replace(b'*',b'').decode()
                name = 'func_' + name.decode()
                print(name)
                print(hex(func_addr))
                idc.set_name(func_addr,name)



rename_func_by_handle(0x65198,0x657A0)


