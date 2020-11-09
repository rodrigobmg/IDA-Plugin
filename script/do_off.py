import idautils
import idc
import ida_search

def make_date_ref():
    ea = 0x9561C
    max_ea = ida_ida.inf_get_max_ea()
    min_ea = ida_ida.inf_get_min_ea()

    while True:
        ea = ida_search.find_unknown(ea, idc.SEARCH_DOWN | idc.SEARCH_NEXT)
        if ea > max_ea:
            break
        size = idc.get_item_size(ea)
        print(hex(ea))

        val = idc.get_wide_dword(ea)
        # if 0xfff38 < val < 0x188544 or 0x1f000000 < val < 0x1ffa3fd9 or 0x20000000 < val < 0x2001ffff:
        #     idc.OpOff(ea, 0, 0)
        if min_ea < val < max_ea:
            idc.op_plain_offset(ea,0,0)




if __name__ == '__main__':
    make_date_ref()