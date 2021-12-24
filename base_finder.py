# -*- coding: utf-8 -*- 

'''
[IDA-python Script]
Finding Base address of an Firmware of BES2300xx
Author:Migraine
'''
# 1. 使用IDA加载固件，选择架构为ARMv7即可
# 2. 运行脚本，将会返回固件的正确加载地址

ea = ida_ida.inf_get_min_ea() #获取当前最小地址
software_init_hook = idc.find_binary(ea,SEARCH_DOWN,'00 20 00 21 04 46 0D 46')  
_libc_fini_array = idc.find_binary(ea,SEARCH_DOWN,'38 B5 07 4B 07 4C ')
_libc_fini_array_pointer = idc.get_wide_dword(software_init_hook+0x30)-1 # 需要减1，因为存储值为libc_fini_array + 1 
base = _libc_fini_array_pointer - _libc_fini_array
print ("software_init_hook : addr = "+hex(software_init_hook))
print ("_libc_fini_array : addr = "+hex(_libc_fini_array ))
print ("_libc_fini_array_pointer : addr = "+hex(_libc_fini_array_pointer ))
print ("[+] BASE ADDRESS : addr = "+hex(base))


#idaapi.auto_make_code(software_init_hook) #自动生成代码
