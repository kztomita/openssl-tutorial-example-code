#include <stdio.h>
#include <openssl/bio.h>

static BIO *bio_stdout = NULL;

void print_bio(BIO *bio_out, BIO *bio)
{
	char buff[1000];
	int ret;

	while (1) {
		ret = BIO_gets(bio, buff, sizeof(buff));
		if (ret <= 0) {
			break;
		}
		BIO_puts(bio_out, buff);
	}
}

int main(int argc, char *argv[])
{
	BIO *bio_in;

	bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);

	/* Create a BIO by helper function. */
	if (argc >= 2) {
		bio_in = BIO_new_file(argv[1], "r");
	} else {
		bio_in = BIO_new_fp(stdin, BIO_NOCLOSE | BIO_FP_TEXT);
	}

	if (bio_in) {
		print_bio(bio_stdout, bio_in);
		BIO_free(bio_in);
	} else {
		fprintf(stderr, "Can't create a bio.\n");
	}

	BIO_free(bio_stdout);

	return 0;
}
