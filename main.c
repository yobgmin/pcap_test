#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <ctype.h>

#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14

/* Ethernet header */
struct ethernet_header {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_int16_t ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct ip_header {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_int16_t ip_len;		/* total length */
    u_int16_t ip_id;		/* identification */
    u_int16_t ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_int16_t ip_sum;		/* checksum */
    u_int32_t ip_src; /* source and dest address */
    u_int32_t ip_des;
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
struct tcp_header {
    u_int16_t th_sport;	/* source port */
    u_int16_t th_dport;	/* destination port */
    u_int32_t th_seq;		/* sequence number */
    u_int32_t th_ack;		/* acknowledgement number */
    u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_int16_t th_win;		/* window */
    u_int16_t th_sum;		/* checksum */
    u_int16_t th_urp;		/* urgent pointer */
};

/* Previous calculate IP
u_char * IPtostr(u_int32_t netIP, u_char * hostIP) {
    hostIP[0] = netIP & 0xff;
    hostIP[1] = (netIP >> 4) & 0xff;
    hostIP[2] = (netIP >> 8) & 0xff;
    hostIP[3] = netIP >> 12;
} */

/* Always TCP, so function has no use.
const u_char * prt(u_char p) {
    switch (p) {
    case 1:
        return "ICMP";
    case 2:
        return "IGMP";
    case 6:
        return "TCP";
    case 17:
        return "UDP";
    default:
        return "error";
    }
} */

int PrintEtherH(struct ethernet_header * ether_h) {
    printf("================ETHERNET================\n");
    printf("des Mac Address : %0x:%0x:%0x:%0x:%0x:%0x\n", ether_h->ether_dhost[0],ether_h->ether_dhost[1],ether_h->ether_dhost[2],ether_h->ether_dhost[3],ether_h->ether_dhost[4],ether_h->ether_dhost[5]);
    printf("src Mac Address : %0x:%0x:%0x:%0x:%0x:%0x\n", ether_h->ether_shost[0],ether_h->ether_shost[1],ether_h->ether_shost[2],ether_h->ether_shost[3],ether_h->ether_shost[4],ether_h->ether_shost[5]);

    printf("================ETHERNET================\n");
    return 0;
}

int PrintIPH(struct ip_header * ip_h) {
    u_char ip[INET_ADDRSTRLEN];

    //u_char ip[4]; Previous print IP
    printf("================IP======================\n");
    printf("IP Version : %d\n", IP_V(ip_h));
    printf("IP Header Size : %d\n", IP_HL(ip_h)*4);
    printf("Type-of Priority Flags : %x\n", ip_h->ip_tos);
    printf("Total IP Length : %d\n", ip_h->ip_len);
    printf("Time To Live : %x\n", ip_h->ip_ttl);
    printf("Protocol Identifier : TCP");

    inet_ntop(AF_INET, &(ip_h->ip_des), ip, INET_ADDRSTRLEN);
    printf("Destination IP : %s\n", ip);
    inet_ntop(AF_INET, &(ip_h->ip_src), ip, INET_ADDRSTRLEN);
    printf("Source IP : %s\n", ip);

    /*
    IPtostr(ip_h->ip_des, ip);
    printf("Destination IP : %d.%d.%d.%d\n", ip[0], ip[1],ip[2],ip[3]);
    IPtostr(ip_h->ip_src, ip);
    printf("Source IP : %d.%d.%d.%d\n", ip[0], ip[1],ip[2],ip[3]);
    */

    printf("================IP======================\n");

    return 0;
}

int PrintTCPH(struct tcp_header * tcp_h) {
    printf("================TCP=====================\n");
    printf("Source Port : %d\n", ntohs(tcp_h->th_sport));
    printf("Destination Port: %d\n", ntohs(tcp_h->th_dport));
    printf("Flag Bits : %x\n", tcp_h->th_flags);
    printf("CheckSum : %x\n", tcp_h->th_sum);

    printf("================TCP=====================\n");
    return 0;
}

int main(int argc, char * argv[])
{
    u_int32_t i, res;
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "port 80";	/* The filter expression */ //-> 80으로 변경한다
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */

    struct ethernet_header *ether_h;
    struct ip_header *ip_h;
    struct tcp_header *tcp_h;
    u_int32_t size_ip;
    u_int32_t size_tcp;
    u_char * http;

    if ( argc != 2) {
        printf("Usage : (sudo) ./pcap_test [device]\n"); // Check argc, too.
        return 0;
    }
    /* Define the device */
    if ( argv[1] == NULL) {
        printf("Usage : ./pcap_test [device]\n");
        return 0;
    }
    dev = argv[1];
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    /* Grab a packet */
    while(1) {
        i=0;
        res = pcap_next_ex(handle, &header, &packet); // header : 패킷이 잡힌 시간, 길이 정보
        if (res == 0 || packet == NULL)
            continue;
        if (res == -1 || res == -2) // Error while grabbing packet.
            break; // I edited it.
        printf("Jacked a packet with length of [%d]\n", (*header).len);
        ether_h = (struct ethernet_header*)(packet);

        if ( ntohs(ether_h->ether_type) != 0x0800) {
            printf("Not IP Header\n");
            continue;

        }
        ip_h= (struct ip_header*)(packet + SIZE_ETHERNET);

        if(ip_h -> ip_p != IPPROTO_TCP) { // when not using tcp Protocol
            printf("Not TCP Protocol\n");
        }
        size_ip = IP_HL(ip_h)*4;
        if (size_ip < 20) {
            printf("   * Invalid IP header length: %u bytes\n", size_ip);
            return 0;
        }

        tcp_h = (struct tcp_header*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp_h)*4;
        if(size_tcp < 20) {
            printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
            return 0;

        }
        /* And close the session */
        printf("%d, %d, %d\n", sizeof(*(ether_h)), sizeof(*(ip_h)), sizeof(*(tcp_h)));

        PrintEtherH(ether_h);
        PrintIPH(ip_h);
        PrintTCPH(tcp_h);

        http = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        if(http != NULL) {
            for(i=0; i<(htons(ip_h->ip_len) - size_ip - size_tcp); i++) {
                if(isprint(http[i]))
                    printf("%c ", http[i]);
                else
                    printf(". ");
                if ( i%16 == 15 )
                    printf("\n");
            }
            printf("\n\n");
        }

    }
    pcap_close(handle);
    return(0);

    //print 가능하면 출력, 아니면 .으로 출력
}
