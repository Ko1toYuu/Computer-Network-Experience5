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
	char packet_filter[] = "ip and udp";
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
	time_and_pkt* tap=new time_and_pkt[1000];//用于存储接收到的包的时间及包的内容
	for (int i = 0; i < 1000; i++)
	{
		time_and_pkt* j = (tap + i * sizeof(time_and_pkt*));
		j->pkt = NULL;
	}
	pcap_loop(adhandle, 0, packet_handler, (u_char*)tap);
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
	(time_and_pkt*)(param);
	time_and_pkt* tak = (time_and_pkt*)param;
	for (int i = 0; i < 1000; i++)
	{
		time_and_pkt* j = (time_and_pkt*)param;
		tak = (j + i * sizeof(time_and_pkt*));
		if (tak->pkt == NULL)
			break;
	}


	FILE* file = fopen("data.csv", "a+");

	/* convert the timestamp to readable format */
	//local_tv_sec = header->ts.tv_sec;
	//ltime = localtime(&local_tv_sec);
	//strftime(timestr, sizeof timestr, "%H:%M:%S,", ltime);
	time_t tt = time(NULL);//这句返回的只是一个时间cuo
	tm* t = localtime(&tt);
	fprintf_s(file, "%02d-%02d-%02d %02d:%02d:%02d,", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
	//printf("%02d-%02d-%02d %02d:%02d:%02d,", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);

	//存储当前包的时间
	tak->minute = t->tm_min;
	tak->pkt = pkt_data;
	time_and_pkt* taki = (time_and_pkt*)param;
	if (tak->minute == taki->minute + 1)//隔1分钟发送来自不同地址包的长度
	{
		//检查有几个不同的ip及mac
		u_char* msrc[100] = { NULL };
		u_char* isrc[100] = { NULL };
		u_char* mdest[100] = { NULL };
		u_char* idest[100] = { NULL };
		int ft[100] = { 0 };//按源分的包总长
		int tt[100] = { 0 };//按目的分的包总长
		int j = 0;
		for (; taki <= tak; taki += sizeof(time_and_pkt))
		{
			j = 0;
			mac_header* mach = (mac_header*)taki->pkt;
			ip_header* iph = (ip_header*)(taki->pkt + sizeof(mac_header));
			//检查有几个不同的源ip
			while (msrc[j] != NULL)
			{
				if (!(mach->src_addr[0] == msrc[j][0] && mach->src_addr[1] == msrc[j][1] && mach->src_addr[2] == msrc[j][2] && mach->src_addr[3] == msrc[j][3]
					&& mach->src_addr[4] == msrc[j][4] && mach->src_addr[5] == msrc[j][5]))
					j++;
				else
					break;
			}				
			if (msrc[j] == NULL)
			{
				msrc[j] = mach->src_addr;
				isrc[j] = iph->saddr;
			}				
			ft[j] += iph->tlen;
			//printf("%d\n", ntohs(ft[j]));

			//检查有几个不同的目的ip
			j = 0;
			while (mdest[j] != NULL)
			{
				if (!(mach->dest_addr[0] == mdest[j][0] && mach->dest_addr[1] == mdest[j][1] && mach->dest_addr[2] == mdest[j][2] && mach->dest_addr[3] == mdest[j][3]
					&& mach->dest_addr[4] == mdest[j][4] && mach->dest_addr[5] == mdest[j][5]))
					j++;
				else
					break;
			}
			if (mdest[j] == NULL)
			{
				mdest[j] = mach->dest_addr;
				idest[j] = iph->daddr;
			}
			tt[j] += iph->tlen;
			//printf("%d\n", ntohs(tt[j]));
		}
		cout << "-----one minute later-----" << endl;
		//输出每个源mac在上一分钟的总传输长度
		for (j = 0; ft[j] != 0; j++)
		{
			cout << "data from:";
			for (int b = 0; b < 5; b++) {
				//源MAC地址
				printf("%02X-", msrc[j][b]);
			}
			printf("%02X,", msrc[j][5]);
			for (int b = 0; b < 3; b++) {
				//源IP地址
				printf("%d.", isrc[j][b]);
			}
			printf("%d,", isrc[j][3]);
			cout << "total length:";
			printf("%d\n", ntohs(ft[j]));
		}
		//输出每个目的mac在上一分钟的总传输长度
		for (j = 0; tt[j] != 0; j++)
		{
			cout << "data to:";
			for (int b = 0; b < 5; b++) {
				//目的MAC地址
				printf("%02X-", mdest[j][b]);
			}
			printf("%02X,", mdest[j][5]);
			for (int b = 0; b < 3; b++) {
				//目的IP地址
				printf("%d.", idest[j][b]);
			}
			printf("%d,", idest[j][3]);
			cout << "total length:";
			printf("%d\n", ntohs(tt[j]));
		}
		//输出结束后清空存储一分钟内数据的数组
		time_and_pkt* czt = (time_and_pkt*)param;
		for (int i = 0; i < 1000; i++)
		{
			if ((czt + i * sizeof(time_and_pkt*))->pkt == NULL)
				break;
			(czt + i * sizeof(time_and_pkt*))->pkt = NULL;
			(czt + i * sizeof(time_and_pkt*))->minute = 0;
		}

	}

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
	/*for (int i = 0; i < 5; i++) {
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
	printf("\n");*/
	fputc('\n', file);
	fclose(file);
}
