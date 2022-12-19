#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#define USE_SNI    1

 /* vhostごとにprotocol version/cipherを指定できるようにする。
  * 0の場合、default(vhosts[0])の設定が使われる。
  */
#define USE_CLIENT_HELLO_CALLBACK  1

struct vhost {
	char *server_name;
	char *cert;	/* サーバー証明書 + 中間証明書 */
	char *private;
	long ssl_options;
	char *cipher_list;
	SSL_CTX *ssl_ctx;
};

/* Virtual Hosts Configuration */
struct vhost vhosts[] = {
	{"www.example.com",
	 "example.com.chained.crt",
	 "example.com.key",
	 0,
	 NULL,
	 NULL,
	},
	{"www.example.net",
	 "example.net.chained.crt",
	 "example.net.key",
	 SSL_OP_NO_TLSv1_3,
	 "ECDHE-RSA-AES128-GCM-SHA256",
	 NULL,
	},
};

struct vhost *find_vhost(const char *server_name)
{
	int i;

	for (i = 0 ; i < sizeof(vhosts) / sizeof(struct vhost) ; i++) {
		/* ケース非依存なホスト名比較などが必要だが省略 */
		if (strcmp(server_name, vhosts[i].server_name) == 0) {
			return &vhosts[i];
		}
	}

	return NULL;
}

/* ref. apache ssl_find_vhost() */
void select_vhost(SSL *ssl, struct vhost *vh)
{
	/* 証明書設定をコピー */
	SSL_set_SSL_CTX(ssl, vh->ssl_ctx);

	SSL_set_options(ssl, SSL_CTX_get_options(vh->ssl_ctx));
}

char *get_servername_from_client_hello(SSL *ssl)
{
	const unsigned char *ext;
	size_t ext_len;
	size_t p = 0;
	size_t server_name_list_len;
	size_t server_name_len;

	if (!SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name,
				       &ext,
				       &ext_len)) {
		return NULL;
	}

	/* length (2 bytes) + type (1) + length (2) + server name (1+) */
	if (ext_len < 6) {
		return NULL;
	}

	/* Fetch Server Name list length */
	server_name_list_len = (ext[p] << 8) + ext[p + 1];
	p += 2;
	if (p + server_name_list_len != ext_len) {
		return NULL;
	}

	/* Fetch Server Name Type */
	if (ext[p] != TLSEXT_NAMETYPE_host_name) {
		return NULL;
	}
	p++;

	/* Fetch Server Name Length */
	server_name_len = (ext[p] << 8) + ext[p + 1];
	p += 2;
	if (p + server_name_len != ext_len) {
		return NULL;
	}

	/* ext_len >= 6 && p == 5 */

	/* Finally fetch Server Name */

	return strndup((const char *) ext + p, ext_len - p);
}

/*
 * SNIで指定されたName based virtual hostのTLS protocol versionを
 * 選択できるようにする。
 * servername_callback()ではTLS protocol versionは既に決まっているので手遅れ。
 * clienthello_callback()で処理する必要がある。
 */
int clienthello_callback(SSL *ssl, int *al, void *arg)
{
	char *servername = NULL;
	struct vhost *vh;

	printf("clienthello_callback\n");

	/* SSL_get_servername()はまだ使えない */

	servername = get_servername_from_client_hello(ssl);
	if (!servername) {
		goto end;
	}

	printf("%s\n", servername);

	vh = find_vhost(servername);
	if (!vh) {
		goto end;
	}

	select_vhost(ssl, vh);

 end:
	if (servername) {
		free(servername);
	}

	return SSL_CLIENT_HELLO_SUCCESS;
}

int servername_callback(SSL *ssl, int *al, void *arg)
{
	struct vhost *vh;

	printf("servername_callback\n");

	const char *server_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (!server_name) {
		/* Client doesn't support SNI. Select default vhost. */
		return SSL_TLSEXT_ERR_OK;
	}

	printf("%s\n", server_name);

	vh = find_vhost(server_name);
	if (!vh) {
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

#if !USE_CLIENT_HELLO_CALLBACK
	select_vhost(ssl, vh);
#endif

	return SSL_TLSEXT_ERR_OK;
}


void cleanup_vhosts()
{
	int i;
	for (i = 0 ; i < sizeof(vhosts) / sizeof(struct vhost) ; i++) {
		if (vhosts[i].ssl_ctx) {
			SSL_CTX_free(vhosts[i].ssl_ctx);
			vhosts[i].ssl_ctx = NULL;
		}
	}
}

int init_virtual_hosts()
{
	int i;
	SSL_CTX *ctx;

	for (i = 0 ; i < sizeof(vhosts) / sizeof(struct vhost) ; i++) {
		ctx = SSL_CTX_new(TLS_server_method());
		if (ctx == NULL) {
			ERR_print_errors_fp(stderr);
			goto error;
		}

		vhosts[i].ssl_ctx = ctx;

		if (!SSL_CTX_use_certificate_chain_file(ctx, vhosts[i].cert)) {
			ERR_print_errors_fp(stderr);
			goto error;
		}
		if (!SSL_CTX_use_PrivateKey_file(ctx, vhosts[i].private, SSL_FILETYPE_PEM)) {
			ERR_print_errors_fp(stderr);
			goto error;
		}

		if (!SSL_CTX_check_private_key(ctx)) {
			ERR_print_errors_fp(stderr);
			goto error;
		}

#if USE_SNI
#if USE_CLIENT_HELLO_CALLBACK
		SSL_CTX_set_client_hello_cb(ctx, clienthello_callback, NULL);
#endif
		SSL_CTX_set_tlsext_servername_callback(ctx, servername_callback);
#endif

		SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

		if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) == 0) {
			ERR_print_errors_fp(stderr);
			goto error;
		}

		if (vhosts[i].ssl_options) {
			SSL_CTX_set_options(ctx, vhosts[i].ssl_options);
		}
		if (vhosts[i].cipher_list) {
			SSL_CTX_set_cipher_list(ctx, vhosts[i].cipher_list);
		}
	}
	return 0;

 error:
	cleanup_vhosts();
	return -1;
}

int process_request(BIO *bio)
{
	char buff[1000];
	const char *response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
	SSL *ssl;
	const char *server_name = NULL;
	int sz;
	int on_going = 0;

	if (BIO_get_ssl(bio, &ssl) > 0) {
		server_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	}
	if (!server_name) {
		server_name = vhosts[0].server_name;	/* default server */
	}

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
	BIO_puts(bio, response);
	BIO_puts(bio, "This is ");
	BIO_puts(bio, server_name);
	BIO_puts(bio, "\r\n");
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
	BIO *bio_ssl = NULL;
	BIO *bio_accept = NULL;

	init_virtual_hosts();

	/* default host(vhosts[0])のSSL_CTXを使う */
	bio_ssl = create_bio_from_ctx(vhosts[0].ssl_ctx);
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

	cleanup_vhosts();

	BIO_free_all(bio_accept);

	/* bio_sslの解放は不要 */

	return 0;

 error:
	cleanup_vhosts();

	if (bio_accept) {
		BIO_free_all(bio_accept);
	}
	if (bio_ssl) {
		BIO_free_all(bio_ssl);
	}

	return -1;
}
