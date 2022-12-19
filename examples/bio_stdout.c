#include <openssl/bio.h>

int main()
{
	/* BIO_CLOSE だとBIO_free()でstdoutもcloseされてしまう。 */
	BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	if (bio_out == NULL) {
		return 1;
	}

	BIO_printf(bio_out, "Hello\n");

	BIO_free(bio_out);

	printf("Hello\n");

	return 0;
}
