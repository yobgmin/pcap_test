#include <pcap.h>
#include <stdio.h>

#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14

/* Ethernet header */
struct ethernet_header {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct ip_header {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    u_int ip_src; /* source and dest address */
    u_int ip_des;
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
struct tcp_header {
    u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    u_int th_seq;		/* sequence number */
    u_int th_ack;		/* acknowledgement number */
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
    u_short th_win;		/* window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
};

u_char * IPtostr(u_int netIP, u_char * hostIP) {
    hostIP[0] = netIP & 0xff;
    hostIP[1] = (netIP >> 4) & 0xff;
    hostIP[2] = (netIP >> 8) & 0xff;
    hostIP[3] = netIP >> 12;
}

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
}

int PrintEtherH(struct ethernet_header * ether_h) {
    printf("================ETHERNET================\n");
    printf("des Mac Address : %0x:%0x:%0x:%0x:%0x:%0x\n", ether_h->ether_dhost[0],ether_h->ether_dhost[1],ether_h->ether_dhost[2],ether_h->ether_dhost[3],ether_h->ether_dhost[4],ether_h->ether_dhost[5]);
    printf("src Mac Address : %0x:%0x:%0x:%0x:%0x:%0x\n", ether_h->ether_shost[0],ether_h->ether_shost[1],ether_h->ether_shost[2],ether_h->ether_shost[3],ether_h->ether_shost[4],ether_h->ether_shost[5]);
    printf("================ETHERNET================\n\n");
    return 0;
}

int PrintIPH(struct ip_header * ip_h) {
    u_char ip[4];
    printf("================IP======================\n");
    printf("IP Version : %d\n", IP_V(ip_h));
    printf("IP Header Size : %d\n", IP_HL(ip_h)*4);
    printf("Type-of Priority Flags : %x\n", ip_h->ip_tos);
    printf("Total IP Length : %d\n", ip_h->ip_len);
    printf("Time To Live : %x\n", ip_h->ip_ttl);
    printf("Protocol Identifier : %s\n", prt(ip_h->ip_p));

    IPtostr(ip_h->ip_des, ip);
    printf("Destination IP : %d.%d.%d.%d\n", ip[0], ip[1],ip[2],ip[3]);
    IPtostr(ip_h->ip_src, ip);
    printf("Source IP : %d.%d.%d.%d\n", ip[0], ip[1],ip[2],ip[3]);
    printf("================IP======================\n\n");

    return 0;
}

int PrintTCPH(struct tcp_header * tcp_h) {
    printf("================TCP=====================\n");
    printf("Source Port : %d\n", tcp_h->th_sport);
    printf("Destination Port: %d\n", tcp_h->th_dport);
    printf("Flag Bits : %x\n", tcp_h->th_flags);
    printf("CheckSum : %x\n", tcp_h->th_sum);

    printf("================TCP=====================\n");
    return 0;
}

int main(int argc, char *argv[])
{
   int i;
   pcap_t *handle;			/* Session handle */
   char *dev;			/* The device to sniff on */
   char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
   struct bpf_program fp;		/* The compiled filter */
   char filter_exp[] = "port 80";	/* The filter expression */ //-> 80으로 변경한다
   bpf_u_int32 mask;		/* Our netmask */
   bpf_u_int32 net;		/* Our IP */
   struct pcap_pkthdr header;	/* The header that pcap gives us */
   const u_char *packet;		/* The actual packet */
   u_char * packet2;

   struct ethernet_header *ether_h;
   struct ip_header *ip_h;
   struct tcp_header *tcp_h;
   u_int size_ip;
   u_int size_tcp;
   u_char * http;

   /* Define the device */
   dev = pcap_lookupdev(errbuf);
   if (dev == NULL) {
       fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
       return(2);
   }
   /* Find the properties for the device */
   if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
       fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
       net = 0;
       mask = 0;
   }
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
       packet = pcap_next(handle, &header); // header : 패킷이 잡힌 시간, 길이 정보
       /* Print its length */
       if (packet == NULL)
           continue;
       printf("Jacked a packet with length of [%d]\n", header.len);
       ether_h = (struct ethernet_header*)(packet);

       ip_h= (struct ip_header*)(packet + SIZE_ETHERNET);
       size_ip = IP_HL(ip_h)*4;
       if (size_ip < 20) {
           printf("   * Invalid IP header length: %u bytes\n", size_ip);
           return;
       }

       tcp_h = (struct tcp_header*)(packet + SIZE_ETHERNET + size_ip);
       size_tcp = TH_OFF(tcp_h)*4;
       if(size_tcp < 20) {
           printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
           return;

       }
       /* And close the session */
   printf("%d, %d, %d\n", sizeof(*(ether_h)), sizeof(*(ip_h)), sizeof(*(tcp_h)));

   PrintEtherH(ether_h);
   PrintIPH(ip_h);
   if(ip_h -> ip_p == 6) { // when using tcp Protocol
       PrintTCPH(tcp_h);
   }

   http = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
   if(http != NULL) {
       for(i=0; i<(header.len - (14+size_ip+size_tcp)); i++) {
           if (http[i] >=0x20 && http[i] <=0x7f)
               printf("%c ", http[i]);
           else
               printf(". ");
           if ( i%16 == 15 )
               printf("\n");
       }
   }

   }
   pcap_close(handle);
   return(0);

   //print 가능하면 출력, 아니면 .으로 출력
}
