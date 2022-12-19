ALL = \
bio_base64_decode \
bio_base64_encode \
bio_file \
bio_file_read_write \
bio_mem_write_read \
bio_new_free \
bio_new_mem_buf \
bio_new_mem_buf_self \
bio_socket \
bio_stdout \
err_get_err \
tls_client \
tls_https_client \
tls_https_server \
tls_https_server_vhost \
tls_server \
tls_server_bio_gets

CC = gcc

CFLAGS = -Wall `pkg-config --cflags openssl`
LDFLAGS = `pkg-config --libs openssl`
SOURCES   = $(wildcard ./*.c)

all: $(ALL)

clean:
	-rm -f *.o
	-rm -f $(ALL)
