#include <stdio.h>
#include <openssl/err.h>

void error1(BIO *bio)
{
	if (BIO_puts(bio, "This triggers an error.") <= 0) {
		fprintf(stderr, "Error Code: %lx\n", ERR_get_error());
        }
}

void error2(BIO *bio)
{
	if (BIO_puts(bio, "This triggers an error.") <= 0) {
		fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
        }
}

void error3(BIO *bio)
{
	if (BIO_puts(bio, "This triggers an error.") <= 0) {
		fprintf(stderr, "%s\n", ERR_reason_error_string(ERR_get_error()));
        }
}

void error4(BIO *bio)
{
	if (BIO_puts(bio, "This triggers an error.") <= 0) {
		ERR_print_errors_fp(stderr);
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

	error1(bio);
	error2(bio);
	error3(bio);
	error4(bio);

	BIO_free(bio);

	return 0;
}
