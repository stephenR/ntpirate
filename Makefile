CC=gcc
CFLAGS=-ggdb -Wall
LDFLAGS=-lpcap -lcrypto
OBJS=ntpirate.o

all: ntpirate

ntpirate: $(OBJS)
	$(CC) -o ntpirate $(LDFLAGS) $(CFLAGS) $(OBJS)
	- sudo setcap "CAP_NET_RAW+ep" ntpirate

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	- rm ntpirate $(OBJS)
