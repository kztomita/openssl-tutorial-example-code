#include <stdio.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

void sending_loop(SSL *ssl)
{
	char buff[256];

	printf("Press Ctrl+d to quit\n");

	while (fgets(buff, sizeof(buff), stdin) != NULL) {
		SSL_write(ssl, buff, strlen(buff));
	}
}

int main()
{
	int sock = -1;
	const char *host_ip = "127.0.0.1";
	uint16_t port = 8000;
	struct sockaddr_in sin;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;

	sock = socket(AF_INET, SOCK_STREAM, 0); 
	if (sock == -1) {
		perror("socket()");
		goto error;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = inet_addr(host_ip);

	if (connect(sock, (struct sockaddr*) &sin, sizeof(sin)) == -1) {
		perror("connect()");
		goto error;
	}

	ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	/* SSL_CTXの設定 */
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

	if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) == 0) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	/* 今回は証明書の検証は省略する */
#if 0
	if (SSL_CTX_set_default_verify_paths(ctx) == 0) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	/* 証明書の検証設定(ホスト名の検証は省略) */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
#endif

	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if (SSL_set_fd(ssl, sock) == 0) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	/* TLS handshake開始 */
	if (SSL_connect(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	sending_loop(ssl);

	SSL_shutdown(ssl);

	SSL_free(ssl); 
	SSL_CTX_free(ctx);
	close(sock);

	return 0;

 error:
	if (ssl) {
		SSL_free(ssl); 
	}
	if (ctx) {
		SSL_CTX_free(ctx);
	}
	if (sock != -1) {
		close(sock);
	}

	return 1;
}
