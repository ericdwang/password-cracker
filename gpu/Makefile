OBJS = main.o clhelp.o
CC = g++
OCL_INC=/usr/local/cuda-4.2/include
OCL_LIB=/usr/local/cuda-4.2/lib64

%.o: %.cpp clhelp.h
	$(CC) -O2 -c $< -I$(OCL_INC)

all: $(OBJS)
	$(CC) main.o clhelp.o -o main -L$(OCL_LIB) -lOpenCL

clean:
	rm -rf $(OBJS) main
