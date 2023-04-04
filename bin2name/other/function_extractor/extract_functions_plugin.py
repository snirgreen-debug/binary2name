import idaapi
import ida_nalt
import ida_funcs
import idautils
import idc
import requests
import json
import re
import os
# from idautils import *
# from idaapi import *
# from idc import *

class FuncExtract(idaapi.plugin_t):
    comment = "todo"
    help = "todo"
    wanted_name = "FuncExtract"
    wanted_hotkey = "Ctrl-Shift-L"
    flags = idaapi.PLUGIN_KEEP

    def _parse_client_response(self):
        response = self.client.response.text
        response = json.loads(response)
        return response

    def init(self):
        idaapi.attach_action_to_menu("Search", "FuncExtract", idaapi.SETMENU_APP)

        self.OUTPUT_DIR = "C://Users/snirg/Desktop/ida_exe/chat_gpt_funcs/functions_extractor/"
        self.functions = [[hex(f.start_ea), hex(f.end_ea), ida_funcs.get_func_name(f.start_ea), [ins for ins in idautils.FuncItems(f.start_ea)], f.start_ea, f.end_ea] for f in [ida_funcs.get_func(i) for i in idautils.Functions()]]
        for f in self.functions:
            disasm = []
            for i in f[3]:
                idc.op_hex(i, 1)
                disasm.append(idc.GetDisasm(i))
            f[3] = disasm
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, _):
        d = self.OUTPUT_DIR
        sub_dirs = [os.path.join(d, o) for o in os.listdir(d) if os.path.isdir(os.path.join(d,o))]
        new_path = d + str(len(sub_dirs)) + '/'
        os.mkdir(new_path)
        self.OUTPUT_DIR = new_path

        c = 0
        for s, e, name, f, s_ea, e_ea in self.functions:
            with open(self.OUTPUT_DIR + name + 'sub_' + hex(s_ea) + '.txt', 'w') as func_file:
                func_file.writelines('\n'.join([i.split(';')[0] for i in f]))
            c += 1
        print(f"{c} functions were added")
        print("done!")


# register IDA plugin
def PLUGIN_ENTRY():
    return FuncExtract()