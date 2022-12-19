#include <openssl/bio.h>

int main()
{
	BIO *mem = BIO_new(BIO_s_mem());
	if (mem == NULL) {
		return 1;
	}

	BIO_free(mem);

	return 0;
}
