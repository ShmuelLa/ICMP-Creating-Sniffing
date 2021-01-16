CC = gcc
CFLAG = -Wall -Wextra -g -o

all: 
	$(CC) icmp.c $(CFLAG) ping.o

git:
	git add -A
	git commit -m "$m"
	git push

test:
	make all
	sudo ./ping.o

nu:
	$(CC) myNuPing.c $(CFLAG) ping.o
	sudo ./ping.o

clean:
	rm -f *.o output/1mb.txt