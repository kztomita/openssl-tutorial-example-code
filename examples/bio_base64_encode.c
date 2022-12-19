#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>

BIO *create_encoder_chain()
{
	BIO *b64 = NULL;
	BIO *bio = NULL;

	b64 = BIO_new(BIO_f_base64());
	if (b64 == NULL) {
		goto error;
	}
	bio = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
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
	BIO *bio_stdin;
	BIO *chain;
	int sz;

	bio_stdin = BIO_new_fp(stdin, BIO_NOCLOSE);

	chain = create_encoder_chain();
	if (chain == NULL) {
		goto error;
	}

	/* binaryデータを読めるようにBIO_gets()ではなくBIO_read()で */
	while ((sz = BIO_read(bio_stdin, buff, sizeof(buff))) > 0) {
		/* base64 filter BIOにwrite操作をするとencodeされる */
		if (BIO_write(chain, buff, sz) <= 0) {
			goto error;
		}
	}

        BIO_flush(chain);

	BIO_free_all(chain);

	BIO_free(bio_stdin);

	return 0;

error:
	if (chain) {
		BIO_free_all(chain);
	}

	BIO_free(bio_stdin);

	ERR_print_errors_fp(stderr);

	return 1;
}
