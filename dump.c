/* (C) 2001-2002 Internet Connection */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
	unsigned *usage_stats;
	unsigned long base, j;
	long need, ips, i;
	int fd, reset;

	reset = 0;
	if (argc >= 2) {
		if (strcmp(argv[1], "-r") == 0) {
			reset = 1;
			argv++; argc--;
		}
	}

	if (argc < 2 || argc > 3) {
		fprintf(stderr, "Usage: %s [-r] scoreboard base\n", argv[0]);
		exit(0);
	}

	if (argc == 3)
		base = htonl(inet_addr(argv[2]));
	else
		base = 0;
	
	fd = open(argv[1], reset ? O_RDWR : O_RDONLY);
	if (fd == -1) {
		perror("open");
		exit(1);
	}
	need = lseek(fd, 0, SEEK_END);
	if (need == 0) {
		fprintf(stderr, "%s is not in-use\n", argv[1]);
		exit(1);
	}

	usage_stats = mmap(0, need, (reset ? PROT_WRITE : 0) | PROT_READ, MAP_SHARED, fd, 0);
	if (!usage_stats) {
		perror("mmap");
		exit(1);
	}

	ips = need / sizeof(unsigned);
	for (i = 0; i < ips; i++) {
		if (usage_stats[i] == 0)
			continue;
		if (base) {
			j = base + i;
			printf("%d.%d.%d.%d\t%u\n",
				(int)(((unsigned char *)&j)[3]),
				(int)(((unsigned char *)&j)[2]),
				(int)(((unsigned char *)&j)[1]),
				(int)(((unsigned char *)&j)[0]),
				usage_stats[i]);
		} else {
			printf("%ld\t%u\n", i, usage_stats[i]);
		}
		if (reset)
			usage_stats[i] = 0;
	}
	munmap(usage_stats, need);
	close(fd);
	exit(0);
}
