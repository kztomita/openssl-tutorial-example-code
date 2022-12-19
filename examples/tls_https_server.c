#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

static const char *cert_file = "localhost.crt";
static const char *private_key_file = "localhost.key";

int process_request(BIO *bio)
{
	char buff[1000];
	const char *response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\ntest\r\n";
	int sz;
	int on_going = 0;

	while ((sz = BIO_gets(bio, buff, sizeof(buff))) > 0) {
		if (on_going == 0 &&
		    buff[0] == 0x0d && buff[1] == 0x0a && buff[2] == 0x00) {
			/* empty line */
			break;
		}
		on_going = buff[sz - 1] == 0x0a ? 0 : 1;

		fputs(buff, stdout);
	}

	/* http response */
	BIO_write(bio, response, strlen(response));
	BIO_flush(bio);

	return 0;
}

BIO *create_bio_from_ctx(SSL_CTX *ctx)
{
	BIO *bio_buf = NULL;
	BIO *bio_ssl = NULL;

	bio_buf = BIO_new(BIO_f_buffer());
	if (!bio_buf) {
		goto error;
	}

	bio_ssl = BIO_new_ssl(ctx, 0);
	if (!bio_ssl) {
		goto error;
	}
	BIO_push(bio_buf, bio_ssl);

	return bio_buf;

error:
	if (bio_ssl) {
		BIO_free(bio_ssl);
	}
	if (bio_buf) {
		BIO_free(bio_buf);
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	SSL_CTX *ctx = NULL;
	BIO *bio_ssl = NULL;
	BIO *bio_accept = NULL;

	ctx = SSL_CTX_new(TLS_server_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if (!SSL_CTX_use_certificate_chain_file(ctx, cert_file)) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	if (!SSL_CTX_use_PrivateKey_file(ctx, private_key_file, SSL_FILETYPE_PEM)) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

	if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) == 0) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	bio_ssl = create_bio_from_ctx(ctx);
	if (!bio_ssl) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	bio_accept = BIO_new_accept("8000");
	if (!bio_accept) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	if (BIO_do_accept(bio_accept) <= 0) {	/* bind */
		ERR_print_errors_fp(stderr);
		goto error;
	}

	/*
	 * ここで指定したbio(chain)はbio_accept内に保持される。
	 * bio_accept解放時に一緒に解放されるので、bioを解放してはいけない。
	 *
	 * Accept BIOは通常、accept時に新しいSocket Bio(accept()が返した
	 * socketを格納したBIO)をbio_acceptにチェーンするだけ。
	 *     Accept BIO -> Socket BIO
	 *
	 * BIO(Chain)を登録しておくと、accept時にBIO_dup_chain()で複製して
	 * Accept BIOの後ろに挿入する。
	 *     Accept BIO -> BIO(Chain) -> Socket BIO
	 *
	 * TLS通信する場合に自動でSSL BIOを挟みたい場合に使用する。
	 * SSL BIOを挟んだ場合は、末尾のSocket bioは使われない。
	 */
	if (BIO_set_accept_bios(bio_accept, bio_ssl) <= 0) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	bio_ssl = NULL;	/* エラー時に解放させないように */

	while (1) {
		BIO *bio = NULL;
		SSL *ssl = NULL;

		if (BIO_do_accept(bio_accept) <= 0) {
			ERR_print_errors_fp(stderr);
			goto error;	/* end */
		}
		printf("Accepted\n");

		/* get new connection */
		bio = BIO_pop(bio_accept);

		if (BIO_do_handshake(bio) <= 0) {
			ERR_print_errors_fp(stderr);
			goto next;
		}
		printf("Handshaked\n");

		if (BIO_get_ssl(bio, &ssl) <= 0) {
			ERR_print_errors_fp(stderr);
			goto error;
		}

		printf("%s\nCipher: %s\n",
		       SSL_get_version(ssl),
		       SSL_get_cipher(ssl));

		process_request(bio);

	next:
		if (bio) {
			BIO_ssl_shutdown(bio);
			BIO_free_all(bio);
		}
	}

	BIO_free_all(bio_accept);

	/* bio_sslの解放は不要 */

	SSL_CTX_free(ctx);

	return 0;

 error:
	if (bio_accept) {
		BIO_free_all(bio_accept);
	}
	if (bio_ssl) {
		BIO_free_all(bio_ssl);
	}
	if (ctx) {
		SSL_CTX_free(ctx);
	}

	return -1;
}
