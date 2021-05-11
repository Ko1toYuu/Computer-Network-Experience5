#include "catch_frame.h"
/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

#define FROM_NIC
int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "tcp";
	struct bpf_program fcode;
#ifdef FROM_NIC
	/* Retrieve the device list */
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n",
			errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	/* Check if the user specified a valid adapter */
	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");

		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
					   // 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
#else
	/* Open the capture file */
	if ((adhandle = pcap_open_offline("C:\\Users\\BD\\Desktop\\aa.pcap",			// name of the device
		errbuf					// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file.\n");
		return -1;
	}

	/* read and dispatch packets until EOF is reached */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);
#endif
	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm* ltime;
	char timestr[16];
	ip_header* ih;
	mac_header* mh;
	//udp_header* uh;
	u_int ip_len;
	//u_short sport, dport;
	//time_t local_tv_sec;
	/*
	 * unused parameter
	 */
	FILE* file = fopen("data.csv", "a+");

	/* convert the timestamp to readable format */
	//local_tv_sec = header->ts.tv_sec;
	//ltime = localtime(&local_tv_sec);
	//strftime(timestr, sizeof timestr, "%H:%M:%S,", ltime);
	time_t tt = time(NULL);//这句返回的只是一个时间cuo
	tm* t = localtime(&tt);


	mh = (mac_header*)pkt_data;

	/* retireve the position of the ip header */
	ih = (ip_header*)(pkt_data + sizeof(mac_header)); //length of ethernet header

	/* retireve the position of the udp header */
	//ip_len = (ih->ver_ihl & 0xf) * 4;
	//uh = (udp_header*)((u_char*)ih + ip_len);

	/* convert from network byte order to host byte order */
	//sport = ntohs(uh->sport);
	//dport = ntohs(uh->dport);

	/* print ip addresses and udp ports */
	u_char* ftp_command = (u_char*)(pkt_data + sizeof(mac_header) + sizeof(ip_header) + 16 * sizeof(u_char));

	if (ftp_command[0] == 'U' && ftp_command[1] == 'S' && ftp_command[2] == 'E' && ftp_command[3] == 'R')
	{
		fprintf_s(file, "%02d-%02d-%02d %02d:%02d:%02d,", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
		//printf("%02d-%02d-%02d %02d:%02d:%02d,", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
		for (int i = 0; i < 5; i++) {
			fprintf_s(file, "%02X-", mh->src_addr[i]);//源MAC地址
			printf("%02X-", mh->src_addr[i]);
		}
		fprintf_s(file, "%02X,", mh->src_addr[5]);
		printf("%02X,", mh->src_addr[5]);
		for (int i = 0; i < 3; i++) {
			fprintf_s(file, "%d.", ih->saddr[i]);//源IP地址
			printf("%d.", ih->saddr[i]);
		}
		fprintf_s(file, "%d,", ih->saddr[3]);
		printf("%d,", ih->saddr[3]);
		for (int i = 0; i < 5; i++) {
			fprintf_s(file, "%02X-", mh->dest_addr[i]);//目的MAC地址
			printf("%02X-", mh->dest_addr[i]);
		}
		fprintf_s(file, "%02X,", mh->dest_addr[5]);
		printf("%02X,", mh->dest_addr[5]);
		for (int i = 0; i < 3; i++) {
			fprintf_s(file, "%d.", ih->daddr[i]);//目的IP地址
			printf("%d.", ih->daddr[i]);
		}
		fprintf_s(file, "%d,", ih->daddr[3]);
		printf("%d,", ih->daddr[3]);
		u_char* a = ftp_command;
		while (a[4] != 0x0d)
		{
			printf("%c", a[4]);
			fprintf_s(file, "%c", a[4]);
			a += sizeof(u_char);
		}
		printf(",");
		fputc(',', file);
	}
	if (ftp_command[0] == 'P' && ftp_command[1] == 'A' && ftp_command[2] == 'S' && ftp_command[3] == 'S')
	{
		u_char* a = ftp_command;
		while (a[4] != 0x0d)
		{
			printf("%c", a[4]);
			fprintf_s(file, "%c", a[4]);
			a += sizeof(u_char);
		}
		printf(",");
		fputc(',', file);
	}
	if (ftp_command[0] == '5' && ftp_command[1] == '3' && ftp_command[2] == '0' && ftp_command[3] == ' ')
	{
		char a[] = "FAILED";
		printf("%s", a);
		fprintf_s(file, "%s", a);
		printf("\n");
		fprintf_s(file, "\n");
	}
	if (ftp_command[0] == '2' && ftp_command[1] == '3' && ftp_command[2] == '0' && ftp_command[3] == ' ')
	{
		char a[] = "SUCCEED";
		printf("%s", a);
		fprintf_s(file, "%s", a);
		printf("\n");
		fprintf_s(file, "\n");
	}
	/*fprintf_s(file, "%02d-%02d-%02d %02d:%02d:%02d,", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
	//printf("%02d-%02d-%02d %02d:%02d:%02d,", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
	for (int i = 0; i < 5; i++) {
		fprintf_s(file, "%02X-", mh->src_addr[i]);//源MAC地址
		printf("%02X-", mh->src_addr[i]);
	}
	fprintf_s(file, "%02X,", mh->src_addr[5]);
	printf("%02X,", mh->src_addr[5]);
	for (int i = 0; i < 3; i++) {
		fprintf_s(file, "%d.", ih->saddr[i]);//源IP地址
		printf("%d.", ih->saddr[i]);
	}
	fprintf_s(file, "%d,", ih->saddr[3]);
	printf("%d,", ih->saddr[3]);
	for (int i = 0; i < 5; i++) {
		fprintf_s(file, "%02X-", mh->dest_addr[i]);//目的MAC地址
		printf("%02X-", mh->dest_addr[i]);
	}
	fprintf_s(file, "%02X,", mh->dest_addr[5]);
	printf("%02X,", mh->dest_addr[5]);
	for (int i = 0; i < 3; i++) {
		fprintf_s(file, "%d.", ih->daddr[i]);//目的IP地址
		printf("%d.", ih->daddr[i]);
	}
	fprintf_s(file, "%d,", ih->daddr[3]);
	printf("%d,", ih->daddr[3]);
	fprintf_s(file, "%d", ntohs(ih->tlen));
	printf("%d", ntohs(ih->tlen));
	printf("\n");
	fputc('\n', file);*/
	fclose(file);
}
