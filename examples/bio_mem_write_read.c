#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/err.h>

void print_bio(BIO *bio)
{
	char buff[1000];
	int ret;

	while (1) {
		/* メモリBIOに書き込まれたデータの読み込み */
		ret = BIO_gets(bio, buff, sizeof(buff));
		if (ret <= 0) {
			break;
		}
		printf("%s", buff);
	}
}

int main()
{
	BIO *bio = BIO_new(BIO_s_mem());
	if (bio == NULL) {
		goto error;
	}
	if (BIO_puts(bio, "content-type: text/html; charset=UTF-8\r\n") <= 0) {
		goto error;
	}
	/* printfのようなformatting関数もある */
	if (BIO_printf(bio, "content-length: %d\r\n", 100) <= 0) {
		goto error;
	}

	/* 書き込んだデータのread */
	print_bio(bio);

	BIO_free(bio);

	return 0;

error:
	if (bio) {
		BIO_free(bio);
	}

	ERR_print_errors_fp(stderr);

	return 1;
}
