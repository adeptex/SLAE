#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[]) {
	char *p;
	
	if (argc < 3) {
		printf("Usage: %s <env var> <binary>\n", argv[0]);
		exit(0);
	}
	
	p = getenv(argv[1]);
	p += (strlen(argv[0]) - strlen(argv[2]))*2;
	printf("%s will be at %p\n", argv[1], p);
}
