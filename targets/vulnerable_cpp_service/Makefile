CC = gcc
CFLAGS = -Wall -O0 -g -fsanitize=address

all: vulnerable_app

vulnerable_app: main.c
	$(CC) $(CFLAGS) -o vulnerable_app main.c

clean:
	rm -f vulnerable_app *.o
