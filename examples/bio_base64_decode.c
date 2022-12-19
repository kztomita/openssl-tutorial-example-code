#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>

BIO *create_decoder_chain()
{
	BIO *b64 = NULL;
	BIO *bio = NULL;

	b64 = BIO_new(BIO_f_base64());
	if (b64 == NULL) {
		goto error;
	}
	/* data source */
	bio = BIO_new_fp(stdin, BIO_NOCLOSE | BIO_FP_TEXT);
	if (bio == NULL) {
		goto error;
	}

        BIO_push(b64, bio);

	return b64;

error:
	if (bio) {
		BIO_free(bio);
	}

	if (b64) {
		BIO_free(b64);
	}

	return NULL;
}

int main()
{
	char buff[1000];
	BIO *bio_stdout;
	BIO *chain;
	int sz;

	bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);

	chain = create_decoder_chain();
	if (chain == NULL) {
		goto error;
	}

	/* base64 filter BIOにread操作をするとdecodeされる */
        while ((sz = BIO_read(chain, buff, sizeof(buff))) > 0) {
		BIO_write(bio_stdout, buff, sz);
	}

	BIO_free_all(chain);

	BIO_free(bio_stdout);

	return 0;

error:
	if (chain) {
		BIO_free_all(chain);
	}

	BIO_free(bio_stdout);

	ERR_print_errors_fp(stderr);

	return 1;
}
