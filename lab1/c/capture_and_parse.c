#include <stdio.h>
#include <time.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <string.h>

/* Standard C include file for I/O functions */
/* Include file for time manipulation functions */
/* Definition of the 'ether_header' structure */
/* Include files for libpcap functions */

int LINE_LEN = 16;

#define TRANSPORT_TCP 6
#define TRANSPORT_UDP 17

/* Prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main(int argc, char **argv)
{
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (argc != 2) {
		printf("Usage: %s network_device_name (e.g., eth0)\n\n", argv[0]);
		return -1;
	}

	/* Open the capture device */
	if ((adhandle = pcap_open_live(argv[1],
								   65536, /* portion of the packet to capture
											 65536 guarantees that the whole
											 packet is captured */
								   1,     /* promiscuous mode */
								   1000,  /* read timeout, 1 second */
								   errbuf /* error buffer */)) == NULL) {
		fprintf(stderr, "Unable to open the adapter: either %s is not supported by libpcap, ", argv[1]);
		fprintf(stderr, "or you do not have 'superuser' privileges\n\n");
		return -1;
	}

	printf("\nlistening on %s...\n", argv[1]);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	pcap_close(adhandle);
	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *tm;
	char timestr[32];
	time_t local_tv_sec;
	struct ether_header *ethptr;

	/* Cast the packet buffer into a pointer to an Ethernet frame */
	ethptr = (struct ether_header *)pkt_data;

	/* Convert the timestamp to a readable format */
	local_tv_sec = header->ts.tv_sec;
	tm = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", tm);
	
    const u_char *data = pkt_data;
    size_t len = header->caplen;
    /* for (size_t i = 0; i < len; ++i) {
        printf("%.2x ", data[i]);
        if ( ((i+1) % LINE_LEN) == 0)
            printf("\n");
    } */

	if (ntohs(ethptr->ether_type) == ETHERTYPE_IP){
        const u_char *ip_header = pkt_data + ETHER_HDR_LEN;

        const char *protocol;
        switch (ip_header[9])
        {
        case TRANSPORT_TCP:
            protocol = "TCP";
            break;
        case TRANSPORT_UDP:
            protocol = "UDP";
            break;
        default:
            protocol = "Unknown";
            break;
        }

        unsigned short int src_port = ip_header[20] << 8 | ip_header[21];
        unsigned short int dst_port = ip_header[22] << 8 | ip_header[23];

        if (dst_port == 80) {
            const u_char tcp_hdr_size = ip_header[20 + 12] >> 4;
            const u_char *payload = ip_header + 20 + (tcp_hdr_size * 4);

            char method[4];
            for (size_t i = 0; i < 4; ++i) {
                method[i] = payload[i];
            }
            if (strncmp(method, "GET ", 4) == 0) {
                printf("GET request\n");
            }
            else if (strncmp(method, "POST", 4) == 0) {
                printf("POST request\n");
            }

            char *host = strstr((char*) payload, "Host:");
            if (host != NULL) {
                host += 5;
                while (*host == ' ') host++;
                printf("Host: %s\n", strtok(host, "\r\n"));
            }
        }

        printf("%s.%.6ld %02x:%02x:%02x:%02x:%02x:%02x->%02x:%02x:%02x:%02x:%02x:%02x %d.%d.%d.%d->%d.%d.%d.%d %s %d->%d\n", 
               timestr, 
               (long)header->ts.tv_usec, 
               ethptr->ether_shost[0], ethptr->ether_shost[1], ethptr->ether_shost[2], ethptr->ether_shost[3], ethptr->ether_shost[4], ethptr->ether_shost[5],
               ethptr->ether_dhost[0], ethptr->ether_dhost[1], ethptr->ether_dhost[2], ethptr->ether_dhost[3], ethptr->ether_dhost[4], ethptr->ether_dhost[5],
               ip_header[12], ip_header[13], ip_header[14], ip_header[15],
               ip_header[16], ip_header[17], ip_header[18], ip_header[19],
               protocol,
               src_port,
               dst_port
               );
    }
	else
		printf("Non IP packet\n");
}

