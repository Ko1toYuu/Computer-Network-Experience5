#define HAVE_REMOTE
#define _CRT_SECURE_NO_WARNINGS
#include <pcap.h>
#include <Packet32.h>
#include <ntddndis.h>
#include <ctime>
#include <iostream>
#include <fstream>
#include <iomanip>
#pragma comment(lib, "Packet")
#pragma comment(lib, "wpcap")
#pragma comment(lib, "WS2_32")
#pragma once
using namespace std;

ofstream outFile;
typedef struct ip_header {
	u_char ver_ihl; // Version (4 bits) + Internet header length(4 bits)
		u_char tos; // Type of service
	u_short tlen; // Total length
	u_short identification; // Identification
	u_short flags_fo; // Flags (3 bits) + Fragment offset(13 bits)
	u_char ttl; // Time to live
	u_char proto; // Protocol
	u_short crc; // Header checksum
	u_char saddr[4]; // Source address
	u_char daddr[4]; // Destination address
	u_int op_pad; // Option + Padding
} ip_header;

typedef struct mac_header {
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
} mac_header;

/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

struct time_and_pkt
{
	int minute;
	const u_char* pkt;
};
