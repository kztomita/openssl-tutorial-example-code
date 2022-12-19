#include <stdio.h>
#include <openssl/bio.h>

static BIO *bio_stdout = NULL;

/*
 * BIO_new()でファイルBIOを作成
 * BIO_new_file()と同等の処理
 */
BIO *create_file_bio(const char *filename, const char *mode)
{
	FILE *file;
	BIO *bio;

	file = fopen(filename, mode);
	if (file == NULL) {
		return NULL;
	}

	bio = BIO_new(BIO_s_file());
	if (bio == NULL) {
		fclose(file);
		return NULL;
	}

	BIO_set_fp(bio, file, BIO_CLOSE | BIO_FP_TEXT);

	return bio;
}

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

int main()
{
	BIO *bio;

	bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);

	bio = create_file_bio("bio_file.c", "r");
	if (bio) {
		print_bio(bio_stdout, bio);
		BIO_free(bio);
	} else {
		fprintf(stderr, "Can't create a bio.\n");
	}

	/* helper function */
	bio = BIO_new_file("bio_file.c", "r");
	if (bio) {
		print_bio(bio_stdout, bio);
		BIO_free(bio);
	} else {
		fprintf(stderr, "Can't create a bio.\n");
	}

	BIO_free(bio_stdout);

	return 0;
}
