/* Elmo's Packet Analysis Program v1.0 */

#include <stdio.h>
#include <pcap/pcap.h>
#include <libnet.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 1;                   /* packet counter */

    /* define/compute ethernet header */
    struct libnet_ethernet_hdr *ethernet = (struct libnet_ethernet_hdr*) packet;

    /* define/compute ip header offset */
    struct libnet_ipv4_hdr *ip = (void *) (packet + 14);

    /* must be TCP IPv4*/
    if(ip->ip_v != 4 || ip->ip_p != IPPROTO_TCP)
        return;

    printf(" [ Packet Number : %d ]\n", count);

    /* print source and destination MAC addresses */
    printf("      Source MAC : %02X:%02X:%02X:%02X:%02X:%02X\n", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
    printf(" Destination MAC : %02X:%02X:%02X:%02X:%02X:%02X\n", ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);

    /* print source and destination IP addresses */
    printf("       Source IP : %s\n", inet_ntoa(ip->ip_src));
    printf("     Destination : %s\n", inet_ntoa(ip->ip_dst));

    /* define/compute tcp header offset */
    struct libnet_tcp_hdr *tcp = (void *) packet + (14 + (ip->ip_hl * 4));

    /* print source and destination Port */
    printf("     Source Port : %d\n", ntohs(tcp->th_sport));
    printf("Destination Port : %d\n", ntohs(tcp->th_dport));
    printf("===========================================\n");

    count++;
    return;
}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;
    pcap_t *handle;
    struct bpf_program fp; // compiled filter program

     bpf_u_int32 maskp;             //subnet mask
     bpf_u_int32 netp;             // ip


    /* Get a device */
    dev = pcap_lookupdev(errbuf);
    if(NULL == dev)
    {
        printf("Error : [%s]\n", errbuf);
        exit(1);
    }
    else
    {
        printf("===========================================\n");
        printf("Network Device Name : [%s]\n", dev);
        printf("===========================================\n");
    }

     /* Get the network address and mask */
     pcap_lookupnet(dev, &netp, &maskp, errbuf);

    /* open device for reading in promiscuous mode */
    handle = pcap_open_live(dev, 1500, 1, 1000, errbuf);

    if(NULL == handle)  // failed to open device
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    else  // check if it is ethernet
    {
        if (pcap_datalink(handle) != DLT_EN10MB)
        {
            fprintf(stderr, "%s is not an Ethernet\n", dev);
            exit(EXIT_FAILURE);
        }
        else
        {
            /* compile the filter expression */
            if (pcap_compile(handle, &fp, "ip", 0, netp) == -1)
            {
                fprintf(stderr, "Couldn't parse filter %s: %s\n",
                "ip", pcap_geterr(handle));
                exit(EXIT_FAILURE);
            }
        }
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
            "ip", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }


    /* loop */
    pcap_loop(handle, 0, got_packet, NULL);

    return 0;
}

/* EOF */
