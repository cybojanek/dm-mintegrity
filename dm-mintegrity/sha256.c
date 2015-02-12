#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "sha256.h"

int main(int argc, char *argv[])
{
	void *input = malloc(4096);
	char digest[33];
	memset(input,0,4096);
	sha256_transform_rorx(input, digest, 1);
	digest[32]=0;
	printf("Hash of all 0 is %s",digest);
	return 0;
}
