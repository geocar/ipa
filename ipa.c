/* (C) 2001-2002 Internet Connection */
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <pcap.h>

#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <sys/file.h>
#include <string.h>

#ifndef DLT_C_HDLC
#define DLT_C_HDLC	12
#endif

#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN		sizeof(struct ether_header)
#endif
#ifndef SLIP_HDRLEN
#ifdef  SLC_BPFHDR
#define SLIP_HDRLEN	SLC_BPFHDR	/* if _BSDI_VERSION >= 199510 */
#else
#define SLIP_HDRLEN	16		/* bpf slip header length */
#endif
#endif


#ifndef PPP_HDRLEN
#ifdef SLC_BPFHDR
#define PPP_HDRLEN	SLC_BPFHDR	/* if _BSDI_VERSION >= 199510 */
#else
#define PPP_HDRLEN	4		/* sizeof(struct ppp_header) */
#endif
#endif

#ifdef  DLT_C_HDLC
#ifndef CHDLC_HDRLEN
#define CHDLC_HDRLEN	4		/* sizeof(struct cisco_hdr) */
#endif
#endif

#ifndef NULL_HDRLEN
#define NULL_HDRLEN	4		/* loopback header length */
#endif

#ifndef __GNUC__
#define inline
#endif

static bpf_u_int32 localnet, netmask;
static unsigned *usage_stats;
static unsigned long need;

static void parse_args(int argc, char *argv[])
{
	char *q;
	int check;

	if (argc < 4) {
		fprintf(stderr, "Usage: %s scoreboard interface {network/mask | network mask}\n", argv[0]);
		exit(1);
	}

	q = strchr(argv[3], '/');
	if (q) {
		/* CIDR style subnet */
		*q = 0; q++;
		netmask = (~0) << (32-(check=atoi(q)));
		if(check < 0 || check > 32) {
			fprintf(stderr, "Cannot parse subnet: /%s\n", q);
			exit(1);
		}
		netmask = ntohl(netmask);
	}

	if (!inet_aton(argv[3], (struct in_addr *)&localnet)) {
		fprintf(stderr, "Cannot parse network: %s\n", argv[3]);
		exit(1);
	}

	if (!q) {
		if (argc < 5) {
			fprintf(stderr, "Usage: %s scoreboard interface {network/mask | network mask}\n", argv[0]);
			exit(1);
		}
		if (!inet_aton(argv[4], (struct in_addr *)&netmask)) {
			fprintf(stderr, "Cannot parse subnet: %s\n", argv[4]);
			exit(1);
		}
	}
}

static void handle_sync(int signo)
{
	msync(usage_stats, need, MS_ASYNC);
}
static void handle_exit(int signo)
{
	munmap(usage_stats, need);
	exit(0);
}

static void inline add_usage(bpf_u_int32 ip, int len)
{
	/* add to the most appropriate place */
	usage_stats[ ntohl(ip & ~netmask) ] += len;
}

static void inline accounting(char *x, int length)
{
	register struct ip *ip;
	register int iplen;
	bpf_u_int32 sip, dip;

	if (length < sizeof(struct ip)) return;
	ip = (struct ip *)x;

	iplen = ntohs(ip->ip_len);
	if (iplen < 1 || length < iplen) return;

	sip = ip->ip_src.s_addr;
	dip = ip->ip_dst.s_addr;

	if ((sip & netmask) == (localnet & netmask)) {
		add_usage(sip, iplen);
	} else if ((dip & netmask) == (localnet & netmask)) {
		add_usage(dip, iplen);
	}
	return;
}

static void if_ether(char *user, struct pcap_pkthdr *h, register u_char *p)
{
	u_int caplen = h->caplen;
	u_int length = h->len;

	if (caplen < ETHER_HDRLEN) return;

	if (ntohs(((struct ether_header *)p)->ether_type) == ETHERTYPE_IP) {
		accounting(p + ETHER_HDRLEN, length - ETHER_HDRLEN);
	}
}
static void if_slip(char *user, struct pcap_pkthdr *h, register u_char *p)
{
	u_int caplen = h->caplen;
	u_int length = h->len;

	if (caplen < SLIP_HDRLEN) return;

	accounting(p + SLIP_HDRLEN, length - SLIP_HDRLEN);
}
static void if_ppp(char *user, struct pcap_pkthdr *h, register u_char *p)
{
	u_int caplen = h->caplen;
	u_int length = h->len;
	register int hdrlen = 0;
	u_short type;
	u_char *packetp;

	if (caplen < PPP_HDRLEN) return;

	packetp = p;
#ifdef SLC_BPFHDRLEN
	p += SLC_BPFHDRLEN;
#endif
	if (p[0] == 0xFF && p[1] == 0x03) {
		/* PPP  AC/CC */
		p += 2;
		hdrlen += 2;
	}
	if (p[0] & 0x01) {
		/* compressed protocol */
		type = *p++;
		hdrlen++;
	} else {
		/* uncompressed */
		type = ntohs(*(u_short *)p);
		p += 2;
		hdrlen += 2;
	}
	if (type == 0x21) {
		/* IP */
#ifdef SLC_BPFHDR
		p = packetp + SLC_BPFHDR;
		hdrlen = SLC_BPFHDR;
#endif
		accounting(p, length - hdrlen);
	}
}

#ifdef DLT_C_HDLC
static void if_chdlc(char *user, struct pcap_pkthdr *h, register u_char *p)
{
	u_int caplen = h->caplen;
	u_int length = h->len;

	if (caplen < CHDLC_HDRLEN) return;

	if (ntohs(*(u_short *)(p + 2)) == 0x0800) { /* IP */
		accounting(p + CHDLC_HDRLEN, length - CHDLC_HDRLEN);
	}
}
#endif

#ifdef DLT_RAW
static void if_rawip(char *user, struct pcap_pkthdr *h, register u_char *p)
{
	accounting(p, h->len);
}
#endif

static void if_null(char *user, struct pcap_pkthdr *h, register u_char *p)
{
	u_int family;
	memcpy(&family, p, sizeof(family));
	if (family == AF_INET)
		accounting(p + NULL_HDRLEN, h->len - NULL_HDRLEN);
}

static struct if_func {
	void (*f)();
	int type;
} if_funcs[] = {
	{       if_ether,       DLT_EN10MB      },      /* Ethernet */
#ifdef  DLT_IEEE802
	{       if_ether,       DLT_IEEE802     },      /* IEEE 802 */
#endif
	{       if_slip,	DLT_SLIP	},      /* SLIP */
#ifdef  DLT_SLIP_BSDOS
	{       if_slip,	DLT_SLIP_BSDOS  },	/* libpcap stupid fake */
#endif
	{       if_ppp,		DLT_PPP		},	/* PPP */
#ifdef  DLT_PPP_BSDOS
	{       if_ppp,		DLT_PPP_BSDOS   },	/* libpcap stupid fake */
#endif
#ifdef  DLT_C_HDLC
	{       if_chdlc,       DLT_C_HDLC      },      /* Cisco HDLC */
#endif
#ifdef  DLT_RAW
	{       if_rawip,       DLT_RAW		},      /* raw IP */
#endif
	{       if_null,	DLT_NULL	},      /* loopback */
	{ NULL, 0 },
};

static pcap_handler lookup_if(int type)
{
	struct if_func *p;

	for (p = if_funcs; p->f != NULL; ++p) {
		if (type == p->type) return p->f;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	const unsigned zero = 0;
	char ebuf[PCAP_ERRBUF_SIZE];
	pcap_t *p;
	unsigned long ips, i;
	int fd;
	char *ifn, *file;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s scoreboard interface [network/mask | network mask]\n", argv[0]);
		exit(1);
	}
	file = argv[1];
	ifn = argv[2];

	p = pcap_open_live(ifn, 65535, 1, 0, ebuf);
	if (!p) {
		fprintf(stderr, "Cannot open interface %s: %s\n", ifn, ebuf);
		exit(1);
	}

	if (argc == 3) {
		if (pcap_lookupnet(ifn, &localnet, &netmask, ebuf) < 0) {
			fprintf(stderr, "Not network on interface %s: %s\n", ifn, ebuf);
			exit(1);
		}
	} else {
		parse_args(argc, argv);
	}

	ips = (~ntohl(netmask))+1;
	fd = open(file, O_RDWR|O_CREAT, 0666);
	if (fd == -1) {
		fprintf(stderr, "Cannot open %s: %s\n", file, strerror(errno));
		exit(1);
	}
	need = ips * sizeof(unsigned);
	i = lseek(fd, 0, SEEK_END);
	if (i == 0) {
		for (i = 0; i < ips; i++)
			write(fd, &zero, sizeof(zero));
	} else if (i != need) {
		fprintf(stderr, "%s was built for another network\n", file);
		exit(1);
	}

	usage_stats = mmap(0, need,
		PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (!usage_stats) {
		fprintf(stderr, "MMAP: %s\n", strerror(errno));
		exit(1);
	}

	signal(SIGTERM, handle_exit);
	signal(SIGINT, handle_exit);
	signal(SIGHUP, handle_sync);
	signal(SIGUSR1, handle_sync);
	if (pcap_loop(p, -1, lookup_if(pcap_datalink(p)), 0) < 0) {
		fprintf(stderr, "pcap_loop failed on interface %s\n", ifn);
		exit(1);
	}
	return 0;
}
