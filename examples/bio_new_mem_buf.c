#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/err.h>

void print_bio(BIO *bio)
{
	char buff[1000];
	int ret;

	while (1) {
		ret = BIO_gets(bio, buff, sizeof(buff));
		if (ret <= 0) {
			break;
		}
		printf("%s", buff);
	}
}

int main()
{
	char string[] = "Hello\n";

        BIO *bio = BIO_new_mem_buf(string, -1);
	if (bio == NULL) {
		ERR_print_errors_fp(stderr);
		return 1;
	}

	print_bio(bio);

#if 0
	if (BIO_puts(bio, "This triggers an error.") <= 0) {
		ERR_print_errors_fp(stderr);
		BIO_free(bio);
		return 1;
        }
#endif

	BIO_free(bio);

	return 0;
}
