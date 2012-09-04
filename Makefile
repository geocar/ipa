CC=gcc
CFLAGS=-O9 -Wall -frerun-loop-opt  -funroll-all-loops
LFLAGS=-static -s

all: ipa-watch ipa-dump
ipa-watch: ipa.o
	$(CC) $(LFLAGS) -o ipa-watch ipa.o -lpcap
ipa-dump: dump.o
	$(CC) $(LFLAGS) -o ipa-dump dump.o
clean:; rm -f ipa-dump ipa-watch ipa.o dump.o
install:
	cp ipa-watch /usr/local/sbin/.
	chmod 0755 /usr/local/sbin/ipa-watch

	cp ipa-dump /usr/local/bin/.
	chmod 0755 /usr/local/bin/ipa-dump
