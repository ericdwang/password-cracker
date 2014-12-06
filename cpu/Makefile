OBJS = main.o sha256.o sha256_functions.o
CC = g++
CFLAGS = -lcrypto -fopenmp

%.o: %.cpp sha256_functions.h
	$(CC) -fopenmp -O3 -c $<

all: $(OBJS)
	$(CC) main.o sha256_functions.o -o main $(CFLAGS)
	$(CC) sha256.o sha256_functions.o -o sha256 $(CFLAGS)

clean:
	rm -rf $(OBJS) main sha256
