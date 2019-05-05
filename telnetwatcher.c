/*
 * telnetwatcher.g
 * Print payload of tcp push packets
 * By J. Stuart McMurray
 * Created 20170719
 * Last Modified 20190504
 */

#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <ctype.h>
#include <err.h>
#include <pcap.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FROMDIR " src"      /* Comms from the server */
#define TODIR   " dst"      /* Comms to the server */
#define SNAPLEN 65535       /* Capture buffer size */
#define UNPRIVUSER "nobody" /* Unpriviledged user to which to drop perms */

/* Default Filter */
#define DEFAULTFILT "(udp%s port %s) or "\
                    "(tcp%s port %s and tcp[tcpflags] & tcp-push != 0)"

/* printhex controls whether or not we print unprintable hex characters */
int printhex = 0;

void usage();
void handler(u_char *usr, const struct pcap_pkthdr *hdr, const u_char *pkt);
void print_packet(const u_char *pkt, bpf_u_int32 len);

/* This program sniffs packets from the wire and prints their payloads to
 * stdout. */
int
main(int argc, char **argv)
{
        char *port, *iface, *filt, *dir;
        int to, from;
        pcap_t *p;
        struct bpf_program prog;
        char errbuf[PCAP_ERRBUF_SIZE];
        bpf_u_int32 net, mask;
        int l2hlen, dltype;
        int promisc;
        int ch, flen, i;
        struct passwd *pw;
        
        to = from = promisc = 0;
        port = NULL;

        /* Get nobody's info */
	if (NULL == (pw = getpwnam(UNPRIVUSER)))
		err(19, "getpwnam");
        if (0 != chdir("/"))
                err(20, "chdir");

        /* We shouldn't need to see anything */
        if (0 != unveil("/dev/bpf", "r"))
                err(17, "unveil");
        if (0 != unveil(NULL, NULL))
                err(18, "unveil");

        /* Parse flags */
        while (-1 != (ch = getopt(argc, argv, "xPhtfp:")))
                switch (ch) {
                        case 'p':
                                port = optarg;
                                break;
                        case 'P':
                                promisc = 1;
                                break;
                        case 't':
                                to = 1;
                                break;
                        case 'f':
                                from = 1;
                                break;
                        case 'x':
                                printhex = 1;
                                break;
                        case 'h':
                        default:
                                usage();
                }
        argc -= optind;
        argv += optind;

        /* Get the capture interface */
        if (0 == argc)
                errx(2, "No interface specified");
        iface = argv[0];
        argc--;
        argv++;

        /* Make sure we either have a port or a filter, but not both */
        if ((1 == argc) && (NULL != port))
                errx(10, "cannot use both a port and a filter");
        else if (0 == argv && (NULL == port))
                errx(11, "either a port or a filter must be specified");


        /* Open the pcap device */
        if (NULL == (p = pcap_open_live(iface, SNAPLEN, 0, 10, errbuf)))
                errx(4, "pcap_open_live: %s", errbuf);
        fprintf(stderr, "Interface: %s\n", iface);

	/* Drop to nobody */
	if (setgroups(1, &pw->pw_gid) == -1)
		err(1, "setgroups() failed");
	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1)
		err(1, "setresgid() failed");
	if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
		err(1, "setresuid() failed");

        /* Netmask for the filter */
        if (-1 == pcap_lookupnet(iface, &net, &mask, errbuf))
                errx(5, "pcap_lookupnet: %s", errbuf);

        /* Make the filter */
        if (0 == argc) {
                dir = "";
                if (to != from) {
                        if (to)
                                dir = TODIR;
                        else if (from)
                                dir = FROMDIR;
                }
                if (0 > asprintf(&filt, DEFAULTFILT, dir, port, dir, port))
                        err(3, "asprintf");
        } else {
                /* Join the rest of the arguments to make the filter */
                flen = 0;
                for (i = 0; i < argc; ++i)
                        flen += strlen(argv[i]) + 1;
                if (NULL == (filt = calloc(flen, sizeof(char))))
                        err(13, "calloc");
                for (i = 0; i < argc; ++i) {
                        /* Spaces between words */
                        if (0 != i)
                                if (strlcat(filt, " ", flen) >= flen)
                                        errx(15, "filter allocation too small");
                        /* Add the word */
                        if (strlcat(filt, argv[i], flen) >= flen)
                                errx(14, "filter allocation too small");
                }
        }

        /* Compile it */
        fprintf(stderr, "Filter: %s\n", filt);
        if (-1 == pcap_compile(p, &prog, filt, promisc, mask))
                errx(12, "pcap_compile: %s", pcap_geterr(p));
        free(filt); filt = NULL;

        /* Apply it */
        if (-1 == pcap_setfilter(p, &prog))
                errx(7, "pcap_setfilter: %s", pcap_geterr(p));
        pcap_freecode(&prog);

	/* Have to call pledge(3) after pcap_setfilter :( */
        if (0 != pledge("stdio", ""))
                err(16, "pledge");

        /* Work out how big the layer-2 header is */
        switch (dltype = pcap_datalink(p)) {
                case DLT_NULL:
                        l2hlen = 4;
                        break;
                case DLT_EN10MB:
                        l2hlen = 14; /* Doesn't handle 802.1Q */
                        break;
                case DLT_RAW:
                        l2hlen = 0;
                        break;
                case DLT_LOOP:
                        l2hlen = 0;
                        break;
#ifdef DLT_LINUX_SLL
                case DLT_LINUX_SLL:
                        l2hlen = 16;
                        break;
#endif /* #ifdef DLT_LINUX_SLL */
                default:
                        errx(8, "unsupported datalink type %s (%s)",
                                        pcap_datalink_val_to_name(dltype),
                                        pcap_datalink_val_to_description(dltype));
        }

        /* Print packet contents */
        if (-1 == pcap_loop(p, -1, handler, (u_char *)&l2hlen))
                err(8, "pcap_loop: %s", pcap_geterr(p));

        return 0;
}

/* handler prints packet bytes */
void
handler(u_char *usr, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
        int off; /* Offset in packet */
        int ipv; /* IP version */
        int l4t; /* Layer-4 type */
        struct tcphdr *th;
        int i;

        /* Skip ethernet header */
        off = *(int *)usr;
        if (off >= hdr->caplen)
                return;

        /* Skip IP header */
        switch (ipv = (pkt[off]) >> 4) {
                case 4: /* IPv4 */
                        if ((off + 9) >= hdr->caplen) 
                                return;
                        l4t = pkt[off + 9];
                        off += 4 * (pkt[off] & 0x0F);
                        break;
                case 6: /* IPv6 */
                        if ((off + 5) >= hdr->caplen)
                                return;
                        l4t = pkt[off + 5];
                        off += 40;
                        break;
                default:
                        fprintf(stderr, "Unexpected IP version %i in", ipv);
                        print_packet(pkt, hdr->caplen);
                        return;
        }
        if (off >= hdr->caplen)
                return;

        /* Skip transport header */
        switch (l4t) {
                case IPPROTO_TCP:
                        if ((off + sizeof(struct tcphdr) >= hdr->caplen))
                                return;
                        th = (struct tcphdr *)(pkt + off);
                        off += 4 * th->th_off;
                        break;
                case IPPROTO_UDP:
                        if ((off + sizeof(struct udphdr) >= hdr->caplen))
                                return;
                        off += sizeof(struct udphdr);
                        break;
                default:
                        return;
        }
        if (off >= hdr->caplen)
                return;

        /* Print payload */
        for (i = off; i < hdr->caplen; ++i)
                if (isprint(pkt[i]) || '\n' == pkt[i])
                        printf("%c", pkt[i]);
                else if (printhex)
                        printf("<%02x>", pkt[i]);
}

/* print_packet prints the len bytes at pkt to stderr in hex followed by a
 * newline. */
void
print_packet(const u_char *pkt, bpf_u_int32 len)
{
        int i;

        for (i = 0; i < (int)len; ++i)
                fprintf(stderr, "%02x", pkt[i]);
        fprintf(stderr, "\n");
}

/* usage prints a helpful usage statement and returns. */
void
usage()
{
        fprintf(stderr, "Usage: %s [-tfPz] [-p port] interface [filter]\n",
                        getprogname());
        fprintf(stderr, "\nPrints the payloads of TCP and UDP packets, either "
                        "to/from a specific port or\n");
        fprintf(stderr, "selected with a BPF filter.\n\n");
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "  -p port  A single port on which to listen for TCP "
                        "and UDP packets\n");
        fprintf(stderr, "  -t       With -p, only print the contents of "
                        "packets going to the port\n");
        fprintf(stderr, "  -f       With -p, only print the contents of "
                        "packets coming from the port\n");
        fprintf(stderr, "  -P       Put the interface in promiscuous mode\n");
        fprintf(stderr, "  -x       Print unprintable characters as <hex>\n");

        exit(9);
}
