import FIDL.decompiler_utils as du
import ida_funcs




def make_name():
    callz = du.find_all_calls_to(f_name='log_info')
    for co in callz:

        # The *second* argument of ``GetProcAddress`` is the API name
        print("====")        
        try:
            if co.args[2].type == 'string':
                api_name = co.args[2].val
            else:
                continue
        except :
            continue

        # double check :)
        # if not du.is_asg(co.node):
        #     continue
        
        if ' ' in api_name:
            continue
        if '\/' in api_name:
            continue
        
        new_name = "func_{}".format(api_name)
        func =  idc.get_func_attr(co.ea, FUNCATTR_START)
        if 'sub_' not in ida_funcs.get_func_name(func):
            continue
        print("====")
        print(hex(func))
        print(new_name)
        idc.set_name(func, new_name, SN_CHECK)


make_name()