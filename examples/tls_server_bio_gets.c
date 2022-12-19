#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

/*
 * SSL *にアクセスするBIOを作成する。
 */
BIO *create_bio_from_ssl(SSL *ssl)
{
	BIO *bio = NULL;
	BIO *bio_ssl = NULL;

	bio = BIO_new(BIO_f_buffer());
	if (!bio) {
		goto error;
	}

	bio_ssl = BIO_new(BIO_f_ssl());
	if (!bio_ssl) {
		goto error;
	}

	BIO_set_ssl(bio_ssl, ssl, BIO_NOCLOSE);
	BIO_push(bio, bio_ssl);

	return bio;

error:
	if (bio_ssl) {
		BIO_free(bio_ssl);
	}

	if (bio) {
		BIO_free(bio);
	}

	return NULL;
}

int read_loop(SSL *ssl)
{
	char buff[1000];
	BIO *bio = NULL;

	bio = create_bio_from_ssl(ssl);
	if (!bio) {
		return -1;
	}

	while (BIO_gets(bio, buff, sizeof(buff)) > 0) {
		fputs(buff, stdout);
	}

	BIO_free_all(bio);

	return 0;
}

int main(int argc, char *argv[])
{
	int sock = -1;
	uint16_t port = 8000;
	struct sockaddr_in listen_addr;
	SSL_CTX *ctx = NULL;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		perror("socket");
		goto error;
	}

	memset(&listen_addr, 0, sizeof(listen_addr));
	listen_addr.sin_family = AF_INET;
	listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	listen_addr.sin_port = htons(port);

	if (bind(sock, (struct sockaddr *) &listen_addr, sizeof(listen_addr)) < 0) {
		perror("bind");
		goto error;
	}

	if (listen(sock, 512) == -1) {
		perror("listen");
		goto error;
	}

	ctx = SSL_CTX_new(TLS_server_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		goto error;
	}


	if (!SSL_CTX_use_certificate_file(ctx, "localhost.crt", SSL_FILETYPE_PEM) ||
	    !SSL_CTX_use_PrivateKey_file(ctx, "localhost.key", SSL_FILETYPE_PEM)) {
		ERR_print_errors_fp(stderr);
		goto error;
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	/*
	 * v1.1.1ではデフォルトでSSL_MODE_AUTO_RETRYは設定されている
	 * https://github.com/openssl/openssl/issues/7908
	 */
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

	if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) == 0) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	printf("Listening port %d ...\n", port);

	while (1) {
		int peer;
		SSL *ssl = NULL;
		int ret = 0;

		peer = accept(sock, NULL, NULL);
		if (peer == -1) {
			perror("accept");
			goto next;
		}
		printf("Accepted\n");

		ssl = SSL_new(ctx);
		if (ssl == NULL) {
			ERR_print_errors_fp(stderr);
			goto next;
		}

		if (SSL_set_fd(ssl, peer) == 0) {
			ERR_print_errors_fp(stderr);
			goto next;
		}

		/* handshake */
		ret = SSL_accept(ssl);
		if (ret <= 0) {
			ERR_print_errors_fp(stderr);
			goto next;
		}
		printf("Handshaked\n");
		printf("%s\nCipher: %s\n",
		       SSL_get_version(ssl),
		       SSL_get_cipher(ssl));

		ret = read_loop(ssl);

	next:
		if (ssl) {
			/*
			 * SSL_ERROR_SYSCALL/SSL_ERROR_SSLが発生していたら
			 * SSL_shutdown()を呼び出してはいけない。
			 */
			if (ret != -2) {
				SSL_shutdown(ssl);
			}
			SSL_free(ssl); 
		}
		if (peer != -1) {
			close(peer);
		}
		printf("Closed\n");
	}

	SSL_CTX_free(ctx);
	close(sock);

	return 0;

 error:
	if (ctx) {
		SSL_CTX_free(ctx);
	}

	if (sock != -1) {
		close(sock);
	}

	return -1;
}
