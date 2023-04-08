#include "add_functions.h"

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	/* Code to allocate the route tables */
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	/* DIE is a arpro for sanity checks */
	DIE(rtable == NULL, "memory");

	/* Code to allocate the arp tables */
	arp_table = malloc(sizeof(struct  arp_entry) * 100000);
	DIE(arp_table == NULL, "memory");
	
	/* Read the static routing table and create the arp table */
	rtable_len = read_rtable(argv[1], rtable);
	arp_table_len = 0;

	qsort(rtable, rtable_len, sizeof(struct route_table_entry), comparator);

	/* Queue in which the packets without a destionation mac will be placed.*/
	queue qpacket = queue_create();
	
	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
		
		/* Extract the Ethernet header from the packet. */

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		
		uint8_t my_mac[6];
		get_interface_mac(interface, my_mac);
		uint8_t broadcast_mac[6];
		memset(broadcast_mac, 0xFF, 6);

		/* If the packet's destination MAC isn't the MAC of the router (from the interface
		 on which the packet was received) and the packet wasn't received following a
		 broadcast, then it is dropped. */
		if (memcmp(my_mac, eth_hdr->ether_dhost, 6) != 0
			&& memcmp(broadcast_mac, eth_hdr->ether_dhost, 6) != 0) {
			continue;
		}

		switch (ntohs(eth_hdr->ether_type)) {
			/* This checks if we got an IPv4 packet */
			case ETHERTYPE_IP: {
				struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
				/* If the router is the destination ("we" are the destination), then the
				 ICMP protocol is called. */
				if (inet_addr(get_interface_ip(interface)) == ip_hdr->daddr) {
					send_icmp(eth_hdr, ip_hdr, buf, ICMP_ECHO_REQUEST, interface, len);
					continue;
				}

				/* This check the ip_hdr integrity using the checksum function.*/
				uint16_t cs = ntohs(ip_hdr->check);
				ip_hdr->check = 0;
				uint16_t new_cs = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
				/* If the checksums aren't equl, the packet is dropped. */
				if (new_cs != cs) {
					continue;
				}

				/* If the ttl is below 2, the ICMP protocol is called to state the error. */
				if (ip_hdr->ttl <= 1) {
					send_icmp(eth_hdr, ip_hdr, buf, ICMP_TIME_EXCEEDED, interface, len);
					continue;
				}

				/* Finding the specific route using get_best_route. */
				struct route_table_entry *rte = get_best_route(ip_hdr->daddr, 0,
															   rtable_len - 1, 0, 0);

				/* If an entry in the route table isn't found, the ICMP protocol is called
				 to state the error. */
				if (!rte) {
					send_icmp(eth_hdr, ip_hdr, buf, ICMP_DESTINATION_UNREACHABLE, interface, len);
					continue;
				}

				/* The ttl and checksum needs to be updated.  */
				ip_hdr->ttl--;
				ip_hdr->check = 0;
				ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

				/* Find the destination ARP address using get_arp_entry.*/
				struct arp_entry *me = get_arp_entry(rte->next_hop);
				
				/* If the entry isn't found, then an ARP Request is made, and the packet
				 is stored in a queue for its destination to be found. */
				if (!me) {
					struct packet curr;
					memcpy(curr.buf, buf, len);
					curr.len = len;
					curr.interface = interface;
					queue_enq(qpacket, &curr);

					send_arp_request(eth_hdr, ip_hdr, rte, buf);
					continue;
				}

				memcpy(eth_hdr->ether_dhost, me->mac, sizeof(me->mac));
				get_interface_mac(rte->interface, eth_hdr->ether_shost);
				
				send_to_link(rte->interface, buf, len);
				break;
			}
			case ETHERTYPE_ARP: {
				struct arp_header *arp_hdr = (struct arp_header *)(buf +
											  sizeof(struct ether_header));
				/* If the packet is for "us". */
				if (inet_addr(get_interface_ip(interface)) == arp_hdr->tpa) {
					/* If the opcode is Request, then a reply is sent. */
					if (ntohs(arp_hdr->op) == ARP_REQUEST) {
						send_arp_reply(eth_hdr, arp_hdr, buf, interface, len);
					} else if (ntohs(arp_hdr->op) == ARP_REPLY) {
						struct arp_entry new_arp_entry;
						/* A new entry is created for the ARP table. */
						new_arp_entry.ip = arp_hdr->spa;
						memcpy(new_arp_entry.mac, arp_hdr->sha, 6);
						arp_table[arp_table_len++] = new_arp_entry;

						queue qpacket_not_sent = queue_create();
						/* Because a new entry is created, each packet verifies if it
						 now has a destination. The remaining packets are put back in 
						 queue. */
						while (!queue_empty(qpacket)) {
							struct packet *p = (struct packet *)queue_deq(qpacket);
							struct ether_header *eth_packet = (struct ether_header *)(p->buf);
							struct iphdr *ip_packet = (struct iphdr *)(p->buf +
													   sizeof(struct ether_header));
							/* A new route is searched. */
							struct route_table_entry *rte = get_best_route(ip_packet->daddr,
															0, rtable_len - 1, 0, 0);
							/* If an entry isn't found, it is put back in the queue. */
							if (!rte) {
								queue_enq(qpacket_not_sent, p);
							} else {
								/* If an entry is found, the MAC is searched and the
								 packet is sent away. */
								struct arp_entry *me = get_arp_entry(rte->next_hop);
								memcpy(eth_packet->ether_dhost, me->mac, sizeof(me->mac));
								get_interface_mac(rte->interface, eth_packet->ether_shost);
								send_to_link(rte->interface, p->buf, p->len);
							}
						}
						qpacket = qpacket_not_sent;
					}
					continue;
				} else {
					/* If it isn't for the router, it simply sends it away, or drops
					 it if a route isn't found. */
					struct route_table_entry *rte = get_best_route(arp_hdr->tpa, 0,
																   rtable_len - 1, 0, 0);
					if (!rte) {
						continue;
					}

					struct arp_entry *me = get_arp_entry(rte->next_hop);
					if (!me) {
						continue;
					}

					memcpy(eth_hdr->ether_dhost, me->mac, sizeof(me->mac));
					get_interface_mac(rte->interface, eth_hdr->ether_shost);
					
					send_to_link(rte->interface, buf, len);
				}
				continue;
				break;
			}
			default:
				continue;
		}
	}
	free(rtable);
	free(arp_table);
}
