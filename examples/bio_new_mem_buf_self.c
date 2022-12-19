#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
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

/* BIO_new_mem_buf()相当の処理 */
BIO *BIO_new_mem_buf_self(const void *buffer, int len)
{
	BIO *bio = NULL;
	BUF_MEM *buf = NULL;
	size_t sz = (len < 0) ? strlen(buffer) : (size_t) len;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL) {
		goto error;
	}

	buf = BUF_MEM_new();
	if (buf == NULL) {
		goto error;
	}

	if (BIO_set_mem_buf(bio, buf, BIO_CLOSE) <= 0) {
		/*
		 * BUF_MEM_free()はbufとbuf->dataを解放する。
		 * 先に buf->data = (void *) buffer; を設定していた場合は、
		 * buf->dataを解放させないようbuf->dataをNULLにしてから
		 * BUF_MEM_free()を呼び出す必要がある。
		 */
		BUF_MEM_free(buf);
		goto error;
	}
	/*
	 * bufはbioに接続されたので、これ以降はBIO_free()で
	 * bufも一緒に解放される(BUF_MEM_free()は必要ない)。
	 */

	buf->data = (void *) buffer;
	buf->length = sz;
	buf->max = sz;

	/*
	 * BIOをread onlyにする。
	 * また、BIO_free()でbuf->dataは解放されなくなる。
	 */
	BIO_set_flags(bio, BIO_FLAGS_MEM_RDONLY);

	return bio;

error:
	if (bio) {
		BIO_free(bio);
	}

	return NULL;
}

int main()
{
	char string[] = "Hello\n";

        BIO *bio = BIO_new_mem_buf_self(string, -1);
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

	/*
	 * read only BIOの場合、BIO_free()はBUF_MEMのbuf->dataは解放しない。
	 * このため、stringに対して解放処理が動作することはない。
	 * C++やRust風に言えばbuffuerに対する所有権は持たず参照しているだけ。
	 * Ref. crypto/bio/bss_mem.c::mem_buf_free()
	 */
	BIO_free(bio);

	return 0;
}
