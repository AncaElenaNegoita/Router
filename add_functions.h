#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP		0x0800	/* IP protocol */
#endif

#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP		0x0806	/* ARP protocol */
#endif

#define ICMP_TIME_EXCEEDED 11
#define ICMP_DESTINATION_UNREACHABLE 3
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0
#define IPPROTO_ICMP IPPROTO_ICMP
#define ARP_ETHER 1
#define ARP_REQUEST 1
#define ARP_REPLY 2

/* Struct to store the data of a packet for queue. */
struct packet {
    char buf[MAX_PACKET_LEN];
    int interface;
    int len;
};

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
struct arp_entry *arp_table;
int arp_table_len;

struct route_table_entry *get_best_route(uint32_t ip_dest, int start, int end, int poz, uint32_t maximum);

struct arp_entry *get_arp_entry(uint32_t given_ip);

int comparator(const void *elem1, const void *elem2);

void send_icmp (struct ether_header *eth_hdr, struct iphdr *ip_hdr, char buf[MAX_PACKET_LEN],
				uint8_t type, int interface, size_t len);

void send_arp_request(struct ether_header *eth_hdr, struct iphdr *ip_hdr, struct route_table_entry* rte,
					  char buf[MAX_PACKET_LEN]);

void send_arp_reply(struct ether_header *eth_hdr, struct arp_header *arp_hdr, char buf[MAX_PACKET_LEN],
					int interface, size_t len);
