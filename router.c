#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <arpa/inet.h>

// tabela de rutare 
struct route_table_entry *rtable;
int rtable_len;

// tabela ARP
struct arp_entry *mac_table;
int mac_table_len;

struct route_table_entry *get_best_route(uint32_t ip_dest) {
	// implementare Longest Prefix Match cu cautare binara
	struct route_table_entry *entry = NULL;

	int low = 0;
	int high = rtable_len - 1;

	while (low <= high) {
		int mid = (low + high) / 2;
		
		if (((ip_dest & rtable[mid].mask) == (rtable[mid].prefix & rtable[mid].mask))) {
			if (entry == NULL || entry->mask < rtable[mid].mask) {
				entry = &rtable[mid];
			}
			low = mid + 1;
		} else if (((ip_dest & rtable[mid].mask) < (rtable[mid].prefix & rtable[mid].mask))) {
			high = mid - 1;
		} else {
			low = mid + 1;
		}
	}

	return entry;
}

struct arp_entry *get_mac_entry(uint32_t given_ip) {
	// aflare adresa MAC destinatie
	for (int i = 0; i < mac_table_len; i++) {
		if (mac_table[i].ip == given_ip) {
			return &mac_table[i];
		}
	}

	return NULL;
}

int cmp(const void* a, const void* b) {
	struct route_table_entry* aux_a = (struct route_table_entry*)a;
	struct route_table_entry* aux_b = (struct route_table_entry*)b;

	if ((aux_a->prefix & aux_a->mask) > (aux_b->prefix & aux_b->mask)) {
		return 1;
	} else if ((aux_a->prefix & aux_a->mask) < (aux_b->prefix & aux_b->mask)) {
		return -1;
	} else if (aux_a->mask > aux_b->mask) {
		return 1;
	} else if (aux_a->mask < aux_b->mask) {
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "memory");

	mac_table = malloc(sizeof(struct arp_entry) * 100);
	DIE(mac_table == NULL, "memory");
	
	rtable_len = read_rtable(argv[1], rtable);
	mac_table_len = parse_arp_table("arp_table.txt", mac_table);

	// sortarea tabelei de rutare pentru a implementa Longest Prefix Match 
	// cu cautare binara
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), cmp);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		if (eth_hdr->ether_type == htons(0x0800)) {
			// IPv4
			struct iphdr* ip_hdr = (struct iphdr*)(buf + sizeof(struct ether_header));

			// verificare daca routerul e destinatia
			if (ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
				// trimitere mesaj de tip ICMP 
				send_icmp(buf, interface);
				continue;
			}

			uint16_t old_checksum = ip_hdr->check;
			ip_hdr->check = 0;
			uint16_t new_checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

			// verificare checksum
			if (new_checksum != old_checksum) {
				continue;
			}

			// cautare in tabela de rutare
			struct route_table_entry *best_entry = get_best_route(ip_hdr->daddr);

			if (best_entry == NULL) {
				// trimitere mesaj ICMP de tip "Destination unreachable"
				send_icmp_err(buf, interface, 3);
				continue;
			}

			// verificare ttl
			if (ip_hdr->ttl <= 1) {
				// trimitere mesaj ICMP de tip "Time exceeded"
				send_icmp_err(buf, interface, 11);
				continue;
			}

			// decrementare ttl
			--(ip_hdr->ttl);
			// actualizare checksum
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

			// interogare tabela ARP pentru a afla adresa MAC destinatie
			struct arp_entry *d_mac = get_mac_entry(best_entry->next_hop);
			memcpy(eth_hdr->ether_dhost, d_mac->mac, 6);

			// aflare adresa MAC pe care se trimite pachetul
			get_interface_mac(best_entry->interface, eth_hdr->ether_shost);

			// trimitere pachet
			send_to_link(best_entry->interface, buf, len);
			
		} else if (ntohs(eth_hdr->ether_type) == 0x0806) {
			// ARP
			continue;
		}
	}
}