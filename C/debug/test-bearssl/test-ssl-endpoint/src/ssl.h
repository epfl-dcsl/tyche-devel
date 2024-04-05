#pragma once

#include "bearssl.h"

#define CHAIN_LEN 1

extern const unsigned char CERT0[];
extern const br_x509_certificate CHAIN[];
extern const br_rsa_private_key RSA;

void* ssl_handler(void*);
void custom_server_profile(br_ssl_server_context* cc,
		const br_x509_certificate* chain, size_t chain_len,
		const br_rsa_private_key* sk);
