
import FIDL.decompiler_utils as du
import ida_funcs
import idc

vul_func = []

printea = lambda a : print(hex(a))


def find_strncpy():
    callz = du.find_all_calls_to(f_name='strncpy')
    for co in callz:
        if len(co.args) > 2:
            if co.args[2].type != 'number':
                vul_func.append(hex(co.ea))
            

def find_snprintf():
    callz = du.find_all_calls_to(f_name=('snprintf'))
    for co in callz:
        if len(co.args) >2:
            if co.args[1].type != 'number':
                printea(co.ea)
                vul_func.append(hex(co.ea))

find_snprintf()
print(vul_func)



