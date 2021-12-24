# -*- coding: utf-8 -*-
'''
[IDA-python Script]
Finding rodata address of an Firmware of BES2300xx
Author:Migraine
'''
# 1. 使用IDA加载固件，选择架构为ARMv7即可
# 2. 运行脚本，将会返回strings段的偏移地址 : 段名[段头，段尾] -> [新段头，新段尾]：偏移

# boot_data_sram
ea = ida_ida.inf_get_min_ea()  # 获取当前最小地址
func1 = idc.find_binary(ea, SEARCH_DOWN, '43 49 40 F2')
# '5F 6F 70 65 72 61 5F 66  6C 75 73 68 00') # opera_flush
opera_flush = idc.find_binary(ea, SEARCH_DOWN, "_opera_flush")
opera_flush_pointer = idc.get_wide_dword(func1 + 0x110)
print("func1 addr : value = "+hex(func1))
print("opera_flush : value = "+hex(opera_flush))
print("opera_flush_pointer : value = "+hex(opera_flush_pointer))

# rodata
ea = ida_ida.inf_get_min_ea()  # 获取当前最小地址
func2 = idc.find_binary(ea, SEARCH_DOWN, '07 EB 85 05 2A 79')
str = idc.find_binary(ea, SEARCH_DOWN, "Invalid data bits param")
str_pointer = idc.get_wide_dword(func2 + 0x92)
if(str_pointer > 0x3d000000 or str_pointer < 0x3c000000):
    str_pointer = idc.get_wide_dword(func2 + 0x94)  # 可能会有字节对齐

print("func2 addr : value = "+hex(func2))
print("str : value = "+hex(str))
print("str_pointer : value = "+hex(str_pointer))

# data
ea = ida_ida.inf_get_min_ea()  # 获取当前最小地址
func3 = idc.find_binary(ea, SEARCH_DOWN, 'C2 f8 b0 30 63 79 05')
str2 = idc.find_binary(ea, SEARCH_DOWN, 'C0 10 10 01 00 01 00 04')
str2_pointer = idc.get_wide_dword(func3 + 0x20)
print("func3 addr : value = "+hex(func3))
print("str2 : value = "+hex(str2))
print("str2_pointer : value = "+hex(str2_pointer))


# Print Result
print("======Data Segment Result=======")

if(opera_flush):
    print(".boot_data_sram: ["+hex(opera_flush-0x228) + "," +
          hex(opera_flush-0x228+0x450)+"] ->" +
          "["+hex(opera_flush_pointer-0x228) + "," +
          hex(opera_flush_pointer-0x228+0x450)+"] :" +
          hex(opera_flush_pointer-opera_flush)
          )
else:
    print("Fail to find .boot_data_sram")

ea = ida_ida.inf_get_max_ea()
size = ea - (str-0x21C)
if(str):
    print(".rodata: ["+hex(str-0x21C) + "," +
          hex(str-0x21C+size)+"] ->" +
          "["+hex(str_pointer-0x21C) + "," +
          hex(str_pointer-0x21C+size)+"] :" +
          hex(str_pointer-str)
          )
else:
    print("Fail to find .rodata")

if(str2):
    print(".data: ["+hex(str2-0x4) + "," +
          "xxxxxx"+"] ->" +
          "["+hex(str2_pointer-0x4) + "," +
          "xxxxxx"+"] :" +
          hex(str2_pointer-str2)
          )
else:
    print("Fail to find .data")
