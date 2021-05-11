
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
