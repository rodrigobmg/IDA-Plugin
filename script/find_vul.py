

import FIDL.decompiler_utils as du
import ida_kernwin
import idautils
import idc
from idaapi import *
import logging

class problems_location():
    def __init__(self, ea, name, src, pattern ,problems):
        self.ea = ea
        self.name = name
        self.src = src
        self.pattern = pattern
        self.problems = problems

class problems_show(ida_kernwin.Choose):
    def __init__(self, title, flags=0, width=None, height=None, embedded=False, modal=False):
        ida_kernwin.Choose.__init__(
                self,
                title,
                [ ["caller", 20 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["function", 8 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["src", 8],
                ["pattern", 8],
                ["problems", 20] ],
                flags = flags,
                width = width,
                height = height,
                embedded = embedded
                )
        self.items = []
    
    def OnClose(self):
        self.items = []

    def OnSelectLine(self, n):
        jumpto(self.items[n].ea)

    def OnGetLine(self, n):
        return self._make_choser_entry(n)

    def OnGetSize(self):
        n = len(self.items)
        return n

    def feed(self, data):
        for item in data:
            self.items.append(item)
        self.Refresh()
        return

    def _make_choser_entry(self, n):
        ea = "%s" % idc.get_func_off_str(self.items[n].ea)
        name = "%s" % self.items[n].name
        pattern = self.items[n].pattern
        src = self.items[n].src

        return [ea, name, src, pattern, ", ".join(self.items[n].problems)]


def format_problems(call_addr, func_name, param_src, pattern_str, problems):
     
    info = problems_location(
        call_addr,
        func_name,
        param_src,
        pattern_str,
        problems,)
    
    return info

def find_snprintf():
    # find snrpintf vul
    callz = du.find_all_calls_to(f_name = 'snprintf')
    for co in callz:
        if len(co.args) > 2:
            if co.args[1].type != 'number':
                print('find vul: {:#x}'.format(co.ea))
                info = format_problems(co.ea, 'snprintf', '', '', '')
                vul_func.append(info)
    return 

def find_strncpy():
    # find strncpy vul
    callz = du.find_all_calls_to(f_name = 'strncpy')
    for co in callz:
        if len(co.args) > 2:
            if co.args[2].type != 'number':
                print('find vul: {:#x}'.format(co.ea))
                info = format_problems(co.ea, 'strncpy', '', '', '')
                vul_func.append(info)
    return

if __name__ == '__main__':
    global vul_func
    vul_func = []
    
    # search ...
    try:
        find_snprintf()
        find_strncpy()
    except exception as e:
        print(str(e))
        pass
    print('search finished!')
    # show result - > 
    result = problems_show('find snprintf and strncpy vul')
    print(vul_func)
    result.Show()
    result.feed(vul_func)
