#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bearssl.h>

static const char* message = "This is a secret message!";
int main() {
	unsigned char key[32] = "0123456789abcdef0123456789abcdef"; 
	unsigned char iv[12] = "0123456789ab"; 
	unsigned char plain[200] = "This is a secret message!";
	unsigned char cipher[200] = {0};
	unsigned char buf[200] = {0};
	size_t key_len = 32, data_len = 32 , v;
	uint32_t c;
  br_aes_ct_ctr_keys aes_ctx;
	br_aes_ct_ctr_init(&aes_ctx, key, key_len);
	memcpy(buf, plain, data_len);
	br_aes_ct_ctr_run(&aes_ctx, iv, 0, buf, data_len);
	for (int i = 0; i < data_len; i++) {
		printf("%02x", buf[i]);
	}
	printf("\n");
	br_aes_ct_ctr_run(&aes_ctx, iv, 0, buf, data_len);
	printf("The result: %s\n", buf);
	return 0;
}

