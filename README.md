# 概要

このリポジトリは https://www.bit-hive.com/documents/openssl-tutorial/ のOpenSSLチュートリアル内で掲載しているサンプルコードをまとめたものです。

チュートリアル内のソースコード名xxxx.cと本リポジトリ内のファイル名が対応しています。
手軽にビルドして動作を確かめたい場合等にお使いください。

なお、本リポジトリの内容をコピペ等して損害が発生しても著者は一切の責任を負いません。

# Build環境

- Linux(Fedora35,Ubuntu22で確認)
- gcc
- OpenSSL 1.1.1/3.0

Buildにはopenssl-devel-*のパッケージが必要です。

# Build手順

    # make

Buildしたバイナリを実行するには、localhost.crt,localhost.key等の証明書や秘密鍵が必要になるものもあります。これらは別途作成してください。

チュートリアルはOpenSSL 1.1.1系を対象にしたものですが、OpenSSL 3.0.7でもBuildできることは確認済みです。

/usr/localなどに個別にインストールしたOpenSSLを使う場合はMakefileのCFLAGS,LDFLAGS,LDLIBSあたりを修正してください。

例) /usr/local/にインストールしたものを使う場合

    CFLAGS = -Wall -I/usr/local/include
    LDFLAGS = -L/usr/local/lib64
    LDLIBS = -lssl -lcrypto

実行

    LD_LIBRARY_PATH=/usr/local/lib64/ ./bio_new_mem_buf


