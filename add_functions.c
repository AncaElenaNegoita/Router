#include "add_functions.h"

/* Returns a pointer to the best matching route, or NULL if there is no matching route.
 It uses binary search in order to find the best match by the longest mask. 
 Implement the LPM algorithm.
*/
struct route_table_entry *get_best_route(uint32_t ip_dest, int start, int end, int poz,
										 uint32_t maximum) {
	if (end < start) {
		if (maximum == 0) {
			return NULL;
		} else {
			return &rtable[poz];
		}
	}

	int mid = (start + end) / 2;
    uint32_t pref = rtable[mid].prefix;
    uint32_t mask = rtable[mid].mask;

	/* Verify if the prefix is the same as the destination and store the position and
	 the mask. */
    if (ntohl(pref & mask) <= ntohl(ip_dest & mask)) {
	    if ((ntohl(pref & mask) == ntohl(ip_dest & mask)) && (maximum < mask)) {
		    poz = mid;
		    maximum = rtable[mid].mask;
	    }
        start = mid + 1;
    } else {
		end = mid - 1;
	}

	return get_best_route(ip_dest, start, end, poz, maximum);
}

/* Returns a pointer to the entry in the arp table that matches with the given ip. */
struct arp_entry *get_arp_entry(uint32_t given_ip) {
	for (int i = 0; i < arp_table_len; i++) {
		if (given_ip == arp_table[i].ip)
			return &arp_table[i];
	}

	return NULL;
}

/* The comparator used for qsort in order to sort the route table in an ascending order. */
int comparator(const void *elem1, const void *elem2) {
    uint32_t mask1 = ((struct route_table_entry *)elem1)->mask;
    uint32_t mask2 = ((struct route_table_entry *)elem2)->mask;
    uint32_t pref1 = ((struct route_table_entry *)elem1)->prefix;
    uint32_t pref2 = ((struct route_table_entry *)elem2)->prefix;

	if ((mask1 & pref1) == (mask2 & pref2)) {
		return ntohl(mask1) - ntohl(mask2);
	} else {
		return ntohl(mask1 & pref1) - ntohl(mask2 & pref2);
	}
}

/* Function that swaps the source and the destionation, and implements an ICMP header
 where the errors or codes for reply are stored. Also, if the type error is 11
 (Time exceeded) or 3(Destination unreachable), the packet will contain also the 
 previous IP header with 8 bytes of data. */
void send_icmp (struct ether_header *eth_hdr, struct iphdr *ip_hdr, char buf[MAX_PACKET_LEN],
				uint8_t type, int interface, size_t len) {
	/* Extract the first IP header and 8 bytes from the previous packet in order to store
	 them in the new packet if there is a type error. */
	char *copy_packet = (char *)(buf + sizeof(struct ether_header));
	int packet_size_rest = 8 + sizeof(struct iphdr);
	char needed[packet_size_rest];
	memcpy(needed, copy_packet, packet_size_rest);
	
	/* Swap the destination and source addresses from both the Ethernet and IP header. */
	uint8_t temp[6];
	memcpy(temp, eth_hdr->ether_dhost, 6);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, temp, 6);

	uint32_t ip_swap = ip_hdr->daddr;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = ip_swap;

	/* Initialise the new header by reseting the ttl, recalculating the checksum and
	 setting the protocol to 1 (reply).*/
	ip_hdr->protocol = 1;
	ip_hdr->ttl = 64;
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)(ip_hdr), sizeof(struct iphdr)));

	/* Build de ICMP header that stores the reply code (0) and the type of action/ error. */
	struct icmphdr new_icmp;
	new_icmp.checksum = 0;
	new_icmp.code = 0;
	memset(&new_icmp.un, 0, sizeof(new_icmp.un));
	new_icmp.checksum = htons(checksum((uint16_t *)(&new_icmp), sizeof(struct icmphdr)));

	if (type == ICMP_ECHO_REQUEST) {
		/* If the type is request, the packet will have an overwritten section for the
		 ICMP header and then it's send.*/
		new_icmp.type = ICMP_ECHO_REPLY;
		memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr), &new_icmp,
			   sizeof(struct icmphdr));
	} else {
		/* If there is an error, it is necessary to have the previous IP header and data
		 (just 8 bytes) to identify the problem. The IP len also modifies to store the
		 ICMP header. */
		new_icmp.type = type;
		ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

		memcpy(buf + sizeof(struct ether_header) + sizeof(struct iphdr), &new_icmp,
			  sizeof(struct icmphdr));

		int size = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
		memcpy(buf + size, needed, packet_size_rest);
		len = size + sizeof(struct iphdr) + 8;
	}
	send_to_link(interface, buf, len);
}

/* Function that sends an ARP request in which it "says" that it needs a target address
 in order to send the packet.*/
void send_arp_request(struct ether_header *eth_hdr, struct iphdr *ip_hdr,
					  struct route_table_entry* rte, char buf[MAX_PACKET_LEN]) {
    uint32_t ip_shost = inet_addr(get_interface_ip(rte->interface));
    uint32_t ip_dhost = rte->next_hop;

    uint8_t my_mac[6];
    get_interface_mac(rte->interface, my_mac);
	uint8_t broadcast_mac[6] = {[0 ... 5] = 0xFF};  // initialize broadcast MAC

	/* The destination becomes the broadcast MAC, and the source the MAC address
	 associated with the interface of the packet. */
    memcpy(eth_hdr->ether_dhost, broadcast_mac, 6);
    memcpy(eth_hdr->ether_shost, my_mac, 6);
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	/* Modify the ARP header, putting in the ARP opcode 1(the code for request). */
    struct arp_header arp_hdr = {
        .htype = htons(ARP_ETHER),
        .ptype = htons(ETHERTYPE_IP),
        .hlen = 6,
        .plen = 4,
        .op = htons(ARP_REQUEST),
        .spa = ip_shost,
        .tpa = ip_dhost
    };
	/* The sender hardware address is the MAC associated with the packet, and the target 
	 is 0 (it is not found yet). */
    memcpy(arp_hdr.sha, my_mac, 6);
    memset(arp_hdr.tha, 0, 6);

    memcpy(buf + sizeof(struct ether_header), &arp_hdr, sizeof(struct arp_header));
    send_to_link(rte->interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));
}


/* Function that sends an ARP reply if it got requested which modifies the hardware address
 and stores a reply code(2). */
void send_arp_reply(struct ether_header *eth_hdr, struct arp_header *arp_hdr,
					char buf[MAX_PACKET_LEN], int interface, size_t len) {
	uint8_t my_mac[6];
	get_interface_mac(interface, my_mac);

	/* In the Ethernet header, the source becomes the MAC address of the packet and the
 	 destination is the sender hardware address.
	 */
	memcpy(eth_hdr->ether_dhost, arp_hdr->sha, 6);
	memcpy(eth_hdr->ether_shost, my_mac, 6);

	/* Swap source and destination IP addresses. */
	uint32_t temp = arp_hdr->spa;
	arp_hdr->spa = arp_hdr->tpa;
	arp_hdr->tpa = temp;

	/* Modify ARP header fields. */
	arp_hdr->op = htons(ARP_REPLY);
	memcpy(arp_hdr->tha, arp_hdr->sha, 6);
	memcpy(arp_hdr->sha, my_mac, 6);

	send_to_link(interface, buf, len);
}
