import idc
import idaapi
import ida_ida
import ida_funcs

max_addr = 	ida_ida.inf_get_max_ea()


def find_a():
    ea = ida_ida.inf_get_min_ea()	
    while ea < max_addr:
        ea = idc.FindUnexplored(ea, idc.SEARCH_DOWN)
        ida_funcs.add_func(ea)


def find_b():
    ea = ida_ida.inf_get_min_ea()	
    while ea < max_addr:
        ea = idaapi.find_not_func(ea, idc.SEARCH_DOWN)
        ida_funcs.add_func(ea)


if __name__ == '__main__':
    find_b()
