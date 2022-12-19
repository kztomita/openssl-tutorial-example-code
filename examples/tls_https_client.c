#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

static BIO *bio_stdout;

int https_get(BIO *bio_ssl, const char *hostname) {
	char buff[1024];
	int size;

	size = snprintf(buff, sizeof(buff), "GET / HTTP/1.1\r\nHost: %s\r\nConnection: Close\r\n\r\n", hostname);
	if (size + 1 > sizeof(buff)) {
		fprintf(stderr, "Insufficient buffer size.\n");
		return -1;
	}
	BIO_puts(bio_ssl, buff);

	while ((size = BIO_read(bio_ssl, buff, sizeof(buff) - 1)) > 0) {
		buff[size] = '\0';
		BIO_write(bio_stdout, buff, size);
	}
	return 0;
}

/* for Debug */
int verify_callback(int preverified, X509_STORE_CTX *ctx)
{
	X509* cert;
	char subject[1024];

	cert = X509_STORE_CTX_get_current_cert(ctx);
	if (cert == NULL) {
		return 0;
	}
	X509_NAME_oneline(X509_get_subject_name(cert), &subject[0], sizeof(subject));
	printf("%d %s\n", preverified, subject);

	return preverified;
}

void enable_hostname_validation(SSL *ssl, const char *hostname)
{
	X509_VERIFY_PARAM *param;

	param = SSL_get0_param(ssl);

	X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
	if (!X509_VERIFY_PARAM_set1_host(param, hostname, 0)) {
		ERR_print_errors_fp(stderr);
	}
}

int main(int argc, char *argv[])
{
	const char *hostname;
	BIO *bio_ssl = NULL;
	SSL_CTX *ctx = NULL;
	SSL *ssl;

	bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);

	if (argc < 2) {
		fprintf(stderr, "Usage:\ntls_https_client <hostname>\n");
		goto error;
	}
	hostname = argv[1];

	ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

	if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) == 0) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if (SSL_CTX_set_default_verify_paths(ctx) == 0) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	/* 証明書の検証設定 */
#if 1
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
#endif

	bio_ssl = BIO_new_ssl_connect(ctx);
	if (bio_ssl == NULL) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if (BIO_get_ssl(bio_ssl, &ssl) <= 0) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	enable_hostname_validation(ssl, hostname);

	/* For SNI */
	SSL_set_tlsext_host_name(ssl, hostname);

	BIO_set_conn_hostname(bio_ssl, hostname);
	BIO_set_conn_port(bio_ssl, "443");
	if (BIO_do_connect(bio_ssl) <= 0) {
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if (https_get(bio_ssl, hostname) == -1) {
		goto error;
	}

	BIO_ssl_shutdown(bio_ssl);

	BIO_free_all(bio_ssl);
	SSL_CTX_free(ctx);

	BIO_free(bio_stdout);

	return 0;

error:
	if (bio_ssl) {
		BIO_free_all(bio_ssl);
	}
	if (ctx) {
		SSL_CTX_free(ctx);
	}

	BIO_free(bio_stdout);

	return 1;
}
