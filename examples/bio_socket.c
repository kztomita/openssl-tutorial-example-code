#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/bio.h>
#include <openssl/err.h>

static BIO *bio_stdout;

BIO *connect_to_remote(const char* hostname, unsigned short port)
{
	struct hostent *ent;
	struct sockaddr_in remote;
	int sock;
	BIO *bio;

	ent = gethostbyname(hostname);
	if (ent == NULL) {
		herror("gethostbyname()");
		return NULL;
	}
	if (ent->h_addrtype != AF_INET) {
		fprintf(stderr, "Can' get ipv4 address.\n");
		return NULL;
	}

	memset(&remote, 0, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_port = htons(port);
	memcpy(&remote.sin_addr, ent->h_addr, sizeof(remote.sin_addr));

	sock = socket(AF_INET, SOCK_STREAM, 0); 
	if (sock == -1) {
		perror("socket()");
		return NULL;
	}

	if (connect(sock, (struct sockaddr*) &remote, sizeof(remote)) == -1) {
		perror("connect()");
		close(sock);
		return NULL;
	}

	bio = BIO_new_socket(sock, BIO_CLOSE);
	if (bio == NULL) {
		close(sock);
		return NULL;
	}

	return bio;
}

void http_get(BIO *bio, const char *hostname)
{
	char buff[1024];
	int size;
	BIO *mem;
	char *request;

	mem = BIO_new(BIO_s_mem());
	if (mem == NULL) {
		ERR_print_errors_fp(stderr);
		return ;
	}

	/*
	 * メモリBIOにBIO_printf()で出力すればバッファサイズを気にせず
	 * formattingできる
	 */
	if (BIO_printf(mem, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: Close\r\n\r\n", hostname) < 0) {
		ERR_print_errors_fp(stderr);
		BIO_free(mem);
		return;
	}

	size = BIO_get_mem_data(mem, &request);

	if (BIO_write(bio, request, size) != size) {
		ERR_print_errors_fp(stderr);
		BIO_free(mem);
		return;
	}
	BIO_flush(bio);
	BIO_free(mem);

	while ((size = BIO_read(bio, buff, sizeof(buff) - 1)) > 0) {
		buff[size] = '\0';
		BIO_write(bio_stdout, buff, size);
	}
}

int main()
{
	const char *hostname ="localhost";
	BIO *bio_sock = NULL;

	bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);

	bio_sock = connect_to_remote(hostname, 80);
	if (bio_sock == NULL) {
		goto error;
	}

	http_get(bio_sock, hostname);

	BIO_free(bio_sock);

	BIO_free(bio_stdout);

	return 0;

error:
	BIO_free(bio_stdout);

	return 1;
}
