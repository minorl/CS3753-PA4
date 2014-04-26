# File: Makefile
# By: Leslie Minor
# Project: CSCI 3753 Programming Assignment 5
# Description:
#	This is the Makefile for PA4.


CC           = gcc

CFLAGSFUSE   = `pkg-config fuse --cflags`
LLIBSFUSE    = `pkg-config fuse --libs`
LLIBSOPENSSL = -lcrypto

CFLAGS = -c -g -Wall -Wextra
LFLAGS = -g -Wall -Wextra

ASSIGNMENT_CODE = pa4_fuse_encfs
.PHONY: all clean

all: pa4 

pa4: $(ASSIGNMENT_CODE)

pa4_fuse_encfs: pa4_fuse_encfs.o aes-crypt.o
	$(CC) $(LFLAGS) $^ -o $@ $(LLIBSFUSE) $(LLIBSOPENSSL)

pa4_fuse_encfs.o: pa4_fuse_encfs.c aes-crypt.h
	$(CC) $(CFLAGS) $(CFLAGSFUSE) $<

aes-crypt.o: aes-crypt.c aes-crypt.h
	$(CC) $(CFLAGS) $<

clean:
	rm -f $(ASSIGNMENT_CODE)
	rm -f *.o
	rm -f *~
