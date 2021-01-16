CC = gcc
CFLAG = -Wall -Wextra -g -o

all: 
	$(CC) icmp.c $(CFLAG) ping.o
	$(CC) sniff.c $(CFLAG) sniff.o -lpcap

git:
	git add -A
	git commit -m "$m"
	git push

test:
	$(CC) icmp.c $(CFLAG) ping.o
	sudo ./ping.o

sniff:
	make all
	sudo ./sniff.o

noor:
	$(CC) noor.c -lpcap $(CFLAG) sniff.o 

clean:
	rm -f *.o output/1mb.txt