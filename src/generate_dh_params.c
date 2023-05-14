/* generate_dh_params.c - Generate DH parameters using OpenSSL 3+ API */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>

static int gendh_cb(EVP_PKEY_CTX *ctx);
static EVP_PKEY *generate_key(void);
static int print_bn(EVP_PKEY *res, const char *name);

int main(void)
{
	EVP_PKEY *key;

	key = generate_key();
	if (!key)
		return 1;

	printf("EVP_PKEY *get_dh2048_key(void)\n{\n");

	if (!print_bn(key, "p"))
		return 1;
	if (!print_bn(key, "g"))
		return 1;
#if 0
	printf(
		"#ifndef OPENSSL_CORE_H\n"
		"# include <openssl/core.h>\n"
		"#endif\n"
		"#ifndef OPENSSL_EVP_H\n"
		"# include <openssl/evp.h>\n"
		"#endif\n"
	);
#endif
	printf(
		"\tEVP_PKEY_CTX *ctx = NULL;\n"
		"\tEVP_PKEY *key = NULL;\n"
		"\tOSSL_PARAM params[] = {\n"
		"\t\tOSSL_PARAM_BN(\"p\", dh2048_p, sizeof(dh2048_p)),\n"
		"\t\tOSSL_PARAM_BN(\"g\", dh2048_g, sizeof(dh2048_g)),\n"
		"\t\tOSSL_PARAM_END\n"
		"\t};\n\n"
		"\tctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);\n"
		"\tif (ctx == NULL)\n"
		"\t\treturn NULL;\n"
		"\tif (EVP_PKEY_fromdata_init(ctx))\n"
		"\t\tEVP_PKEY_fromdata(ctx, &key, EVP_PKEY_KEY_PARAMETERS, params);\n"
		"\t\n"
		"\tEVP_PKEY_CTX_free(ctx);\n"
		"\treturn key;\n"
		"}\n"
	);

	return 0;
}

static EVP_PKEY *generate_key(void)
{
	int rc;
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *res = NULL;

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
	if (ctx == NULL)
	{
		fprintf(stderr, "Failed EVP_PKEY_CTX_new_from_name\n");
		return NULL;
	}

	EVP_PKEY_CTX_set_cb(ctx, gendh_cb);

	rc = EVP_PKEY_paramgen_init(ctx);
	if (rc == 0)
	{
		fprintf(stderr, "Failed EVP_PKEY_paramgen_init\n");
		return NULL;
	}
	rc = EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, 2048);
	if (rc == 0)
	{
		fprintf(stderr, "Failed EVP_PKEY_CTX_set_dh_paramgen_prime_len\n");
		return NULL;
	}
	rc = EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, 2);
	if (rc == 0)
	{
		fprintf(stderr, "Failed EVP_PKEY_CTX_set_dh_paramgen_generator\n");
		return NULL;
	}

	fprintf(stderr, "*** Generating DH Parameters for SSL/TLS (may take some time) ***:\n");
	rc = EVP_PKEY_paramgen(ctx, &res);
	fprintf(stderr, "\n");
	if (rc == 0)
	{
		fprintf(stderr, "Failed EVP_PKEY_paramgen\n");
		return NULL;
	}

	EVP_PKEY_CTX_free(ctx);
	return res;
}

static int print_bn(EVP_PKEY *res, const char *name)
{
	int rc;
	int i;
	int size;
	BIGNUM *bn = NULL;
	unsigned char buffer[512];

	rc = EVP_PKEY_get_bn_param(res, name, &bn);
	if (rc == 0)
	{
		fprintf(stderr, "Failed EVP_PKEY_get_bn_param\n");
		return 0;
	}

	rc = BN_bn2nativepad(bn, buffer, sizeof(buffer));
	if (rc < 0)
	{
		fprintf(stderr, "Failed BN_bn2nativepad\n");
		return 0;
	}

	size = BN_num_bytes(bn);

	printf("\tstatic unsigned char dh2048_%s[]={\n\t\t", name);

	for (i = 0; i < size; i += 16)
	{
		int j;
		for (j = 0; j < 16 && i+j < size; j++)
		{
			printf("0x%02x", buffer[i+j]);
			if (i+j < size - 1)
				putchar(',');
		}

		if (i+j < size)
			printf("\n\t\t");
	}
	printf("\n\t};\n");

	BN_free(bn);
	return 1;
}

static int gendh_cb(EVP_PKEY_CTX *ctx)
{
	static const char symbols[] = ".+*\n";
	int p = EVP_PKEY_CTX_get_keygen_info(ctx, 0);
	if (p)
	{
		char c = (p >= 0 && (size_t)p < sizeof(symbols) - 1) ? symbols[p] : '?';
		fputc(c, stderr);
		fflush(stderr);
	}
	return 1;
}
