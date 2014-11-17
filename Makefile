CC = gcc
CFLAGS = -lcrypto

all: sha256 main

sha256: sha256.c
	$(CC) sha256.c sha256_functions.c $(CFLAGS) -o sha256

main: main.c
	$(CC) main.c sha256_functions.c $(CFLAGS) -o main
