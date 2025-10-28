// Standard C include file for I/O functions
#include <stdio.h>

// Include files for libpcap functions
#include <pcap.h>

#define LINE_LEN 16

int main(int argc, char **argv)
{
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    u_int i=0;
    int res;
	
    if (argc != 2)
    {	
        printf("Usage: %s filename\n\n", argv[0]);
        return -1;
    }
	
    /* Open the capture file */
    /* Parameters: name of the file to open, error buffer */
    if ((fp = pcap_open_offline(argv[1], errbuf)) == NULL)
    {
        fprintf(stderr,"Unable to open file %s.\n\n", argv[1]);
        return -1;
    }
	
    /* Retrieve packets from the file */
    while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
    {
        /* print pkt timestamp and pkt len */
        printf("%ld:%ld (%d)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
		
        /* Print the packet */
        for (i=0; i < header->caplen; i++)
        {
            printf("%.2x ", pkt_data[i]);

            if ( ((i+1) % LINE_LEN) == 0)
               printf("\n");
        }
		
        printf("\n\n");
    }
	
    if (res == -1)
        printf("Error reading the packets: %s\n", pcap_geterr(fp));
	
    pcap_close(fp);
    return 0;
}

