#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>

#define PORT_NO 0
#define PACKET_SIZE 64

int pingloop = 1;

//structure of packet to be sent for communication
struct packet_structure
{

    struct icmphdr header;
    char message[PACKET_SIZE - sizeof(struct icmphdr)];

};

//Handler to catch keyboard interrupt
void intHandler(int dummy)
{

    pingloop = 0;

}

unsigned short checksum(void *b, int len); // function to validate packets
char *dns_address(char *ip_address, struct sockaddr_in6 *address_container);
char *dns_lookup(char *host_name, struct sockaddr_in *addr_con);
void echo_request(int sockfd, struct sockaddr_in *address_container, int ttl, char *ip_address, char *hostname);

int main(int argc, char *argv[])
{

    if(argc != 3)
    {
        printf("Wrong input given. Format is %s Hostname TTL\n", argv[0]);
        return 0;
    }

    char *ip_address;
    struct sockaddr_in address_container;
    struct sockaddr_in6 add_container;
    int sockfd;
    char buffer[16];
    int ttl = atoi(argv[2]);



    if(inet_pton(AF_INET, argv[1], buffer))
    {
        printf("IPv4 address\n");
        ip_address = dns_lookup(argv[1], &address_container);
    }
    else if(inet_pton(AF_INET6, argv[1], buffer))
    {
        printf("IPv6 address\n");
        ip_address = dns_address(argv[1], &add_container);
    }
    else
    {
        printf("Host name\n");
        ip_address = dns_lookup(argv[1], &address_container);
    }

//    ip_address = dns_address(argv[1], &address_container);

    if(ip_address == NULL)
    {
        printf("Could not resolve hostname\n");
        return 0;
    }
    
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if(sockfd < 0)
    {
        printf("Socket file descriptor not received \n");
    }
    else
    {
        printf("Socket file descriptor received\n");
    }

    signal(SIGINT, intHandler);

    echo_request(sockfd, &address_container, ttl, ip_address, argv[1]);

    return 0;
}

char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con)
{
    printf("\nResolving DNS..\n");
    struct hostent *host_entity;
    char *ip=(char*)malloc(NI_MAXHOST*sizeof(char));
    int i;

    if ((host_entity = gethostbyname(addr_host)) == NULL)
    {
        // No ip found for hostname
        return NULL;
    }

    //filling up address structure
    strcpy(ip, inet_ntoa(*(struct in_addr *)
                          host_entity->h_addr));

    (*addr_con).sin_family = host_entity->h_addrtype;
    (*addr_con).sin_port = htons (PORT_NO);
    (*addr_con).sin_addr.s_addr  = *(long*)host_entity->h_addr;
    return ip;

}

void echo_request(int sockfd, struct sockaddr_in  *address_container, int ttl, char *ip_address, char *hostname)
{

    int sent_msg_count = 0, received_msg_count = 0;
    int recv_addr_len, i;
   
    long double rtt_msec = 0, total_msec = 0;
    struct packet_structure packet;
    struct sockaddr_in receiving_addr;
    int packet_sent_flag = 1;
    struct timespec start_time, end_time, start_total, end_total;
    struct timeval tv_out;
    tv_out.tv_sec = 1;
    tv_out.tv_usec = 0;


    clock_gettime(CLOCK_MONOTONIC, &start_total);
    if(setsockopt(sockfd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0)
    {
        printf("Setting socket options to TTL failed \n");
        return;
    }

    else
    {
        printf("Socket set to TTL\n");
    }

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out , sizeof tv_out);

    while(pingloop)
    {
        
        packet_sent_flag = 1;
        
        bzero(&packet, sizeof(packet));

        packet.header.type = ICMP_ECHO;
        packet.header.un.echo.id = getpid();

        for(i = 0; i < sizeof(packet.message) - 1; i++)
                packet.message[i] = i + '0';

        packet.message[i] = 0;
        packet.header.un.echo.sequence = sent_msg_count;
        sent_msg_count += 1;
        packet.header.checksum = checksum(&packet, sizeof(packet));
        ///add checksum fuction and line

        usleep(1000000);

        clock_gettime(CLOCK_MONOTONIC, &start_time);

        if( sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr*) address_container, sizeof(*address_container)) <= 0)
        {
            printf(" packet sending failed \n");
            packet_sent_flag = 0;
        }
        
        recv_addr_len = sizeof(receiving_addr);

        if( recvfrom(sockfd, &packet, sizeof(packet), 0, (struct sockaddr*)&receiving_addr, &recv_addr_len) <= 0)
        {

            printf("packet receive failed\n");
        }

        else
        {

            clock_gettime(CLOCK_MONOTONIC, &end_time);

            double timeElapsed = ((double)(end_time.tv_nsec - start_time.tv_nsec))/1000000.0;
            rtt_msec = (end_time.tv_sec-  start_time.tv_sec) * 1000.0  + timeElapsed;

            if(packet_sent_flag)
            {
                    if(!(packet.header.type == 69 && packet.header.code == 0))
                    {

                        printf("Error. Packet received with ICMP type %d code %d\n", packet.header.type, packet.header.code);

                    }
                    else
                    {

                        printf("%d bytes from %s, msg_seq = %d ttl = %d rtt = %Lf ms.\n", PACKET_SIZE, hostname, sent_msg_count, ttl, rtt_msec);
                    
                        received_msg_count++;
                    }

            }

        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end_total);
    double timeElapsed = ((double)(end_total.tv_nsec - start_total.tv_nsec))/1000000.0;

    total_msec = (end_total.tv_sec-start_total.tv_sec)*1000.0+timeElapsed;

    printf("\n**** packets summary ****\n");
    printf("\n%d packets sent, %d packets received, %f percentpacket loss. Total time: %Lf ms.\n\n",sent_msg_count, received_msg_count,((sent_msg_count - received_msg_count)/sent_msg_count) * 100.0,total_msec);

}

char *dns_address(char *host_name, struct sockaddr_in6 *address_container)
{

    struct hostent *entity;
    //char *ipv;
    struct in6_addr addr;
    inet_aton(host_name, &addr);
    char *ip = (char*)malloc(NI_MAXHOST * sizeof(char));
//    struct in_addr ip;
    int i;
    //socklen_t len;
    
//    inet_aton(host_name, &ip);

    if((entity = gethostbyaddr(&addr, sizeof(addr), AF_INET6)) == NULL)
    {
       return NULL;
    }
    
    //strcpy(ip, inet_ntoa(*(struct in_addr *) entity->h_addr));

    printf("printing  %s \n", entity -> h_name);
    (*address_container).sin6_family = entity -> h_addrtype;
    (*address_container).sin6_port = htons (PORT_NO);
    strcpy(((*address_container).sin6_addr.s6_addr),(*(long*)entity -> h_addr));

    return ip;
}

unsigned short checksum(void *b, int len)
{

    unsigned short *buf = b;
    unsigned int sum=0;
    unsigned short result;
 
      for ( sum = 0; len > 1; len -= 2 )
          sum += *buf++;
      if ( len == 1 )
          sum += *(unsigned char*)buf;
      sum = (sum >> 16) + (sum & 0xFFFF);
      sum += (sum >> 16);
      result = ~sum;
      return result;

}


