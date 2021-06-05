#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "pcap.h"
#include <stdbool.h>
#include <time.h>
#define FILTER "ip and udp"
//�����澯0.5M
#define LIMIT 524288
//ͳ�����ݳ���ʱ�������30s
#define STATISTIC_TIME 30000
//������
int packet_counter = 0;

int sec = -1;
int min = -1;
//����ļ�
FILE* fp=NULL;
//���������ʱ
ULONGLONG last_sec;
//ͳ�Ʊ������ʱ
ULONGLONG last_recv_output;
ULONGLONG last_send_output;
//�洢��¼
char result[100];
/*MAC��ַ*/
typedef struct MAC_add {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}MAC_add;
typedef struct MAC_header {
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
} MAC_header;

/*IP��ַ*/
typedef struct IP_add{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}IP_add;

/* IPv4 ͷ��*/
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	IP_add	saddr;		// Source address
	IP_add	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/* UDPͷ��*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;
/*tcp ͷ��*/
typedef struct tcp_header
{
	unsigned short src_port;   //Դ�˿ں�
	unsigned short dst_port;   //Ŀ�Ķ˿ں�
	unsigned int seq_no;    //���к�
	unsigned int ack_no;    //ȷ�Ϻ�
#if LITTLE_ENDIAN
	unsigned char reserved_1 : 4; //����6λ�е�4λ�ײ�����
	unsigned char thl : 4;    //tcpͷ������
	unsigned char flag : 6;    //6λ��־
	unsigned char reseverd_2 : 2; //����6λ�е�2λ
#else
	unsigned char thl : 4;    //tcpͷ������
	unsigned char reserved_1 : 4; //����6λ�е�4λ�ײ�����
	unsigned char reseverd_2 : 2; //����6λ�е�2λ
	unsigned char flag : 6;    //6λ��־ 
#endif
	unsigned short wnd_size;   //16λ���ڴ�С
	unsigned short chk_sum;   //16λTCP�����
	unsigned short urgt_p;    //16Ϊ����ָ��
}tcp_header;

/*�ж�IP��Mac��ַ�Ƿ����*/
bool Equal(IP_add* IP_ADDR_0, IP_add* IP_ADDR_1, MAC_add* MAC_ADDR_0, MAC_add* MAC_ADDR_1) {
	if ((IP_ADDR_0->byte4 == IP_ADDR_1->byte4) && (IP_ADDR_0->byte1 == IP_ADDR_1->byte1) &&
		(IP_ADDR_0->byte2 == IP_ADDR_1->byte2) && (IP_ADDR_0->byte3 == IP_ADDR_1->byte3))
	{
		if ((MAC_ADDR_0->byte6 == MAC_ADDR_1->byte6) && (MAC_ADDR_0->byte1 == MAC_ADDR_1->byte1) &&
			(MAC_ADDR_0->byte2 == MAC_ADDR_1->byte2) && (MAC_ADDR_0->byte3 == MAC_ADDR_1->byte3) &&
			(MAC_ADDR_0->byte4 == MAC_ADDR_1->byte4) && (MAC_ADDR_0->byte5 == MAC_ADDR_1->byte5))
			return true;//���
		else return false;
	}
	else return false;
}
//������¼
typedef struct FLOW_STATEMENT {
	MAC_add MAC;		//Դ/Ŀ��MAC��ַ
	IP_add IP;			//Դ/Ŀ��IP��ַ
	unsigned total;	//һ��ʱ���ڵ�������
}FLOW_STATEMENT;


//������¼��
typedef struct FLOW_LIST {
	FLOW_STATEMENT* HEAD;//��ͷ
	int length;//��
}FLOW_LIST;

FLOW_LIST* flow_alarm_list;//���Ʊ�
FLOW_LIST* flow_recv_list;//�ܵ���
FLOW_LIST* flow_send_list;//���ͱ�
//CSV��־��¼����
typedef struct CSV_FORMAT {
	struct tm* time;	//ʱ��
	MAC_add srcMac;		//ԴMAC��ַ
	IP_add srcIP;			//ԴIP��ַ
	MAC_add desMac;		//Ŀ��MAC��ַ
	IP_add desIP;			//Ŀ��IP��ַ
	int len;				//֡����
}CSV_FORMAT;
/*�������������д��CSV���ַ����ĺ���*/
char* CSVFORMAT_to_str(CSV_FORMAT* csv_format) {

	memset(result, 0, sizeof(result));
	//���ʱ��
	char timestr[20];
	strftime(timestr, sizeof(timestr), "%Y/%m/%d %H:%M:%S", csv_format->time);

	char src_mac_str[18];//ԴMac��ַ
	char src_ip_str[16]; //Դip��ַ
	char des_mac_str[18];//Ŀ��Mac��ַ
	char des_ip_str[16]; //Ŀ��ip��ַ

	//���ԴMAC��ַ
	sprintf(src_mac_str, "%02X-%02X-%02X-%02X-%02X-%02X",
		csv_format->srcMac.byte1,
		csv_format->srcMac.byte2,
		csv_format->srcMac.byte3,
		csv_format->srcMac.byte4,
		csv_format->srcMac.byte5,
		csv_format->srcMac.byte6);
	//���ԴIP��ַ
	sprintf(src_ip_str, "%3d:%3d:%3d:%3d",
		csv_format->srcIP.byte1,
		csv_format->srcIP.byte2,
		csv_format->srcIP.byte3,
		csv_format->srcIP.byte4);
	//���Ŀ��MAC��ַ
	sprintf(des_mac_str, "%02X-%02X-%02X-%02X-%02X-%02X",
		csv_format->desMac.byte1,
		csv_format->desMac.byte2,
		csv_format->desMac.byte3,
		csv_format->desMac.byte4,
		csv_format->desMac.byte5,
		csv_format->desMac.byte6);
	//���Ŀ��IP��ַ
	sprintf(des_ip_str, "%3d:%3d:%3d:%3d",
		csv_format->desIP.byte1,
		csv_format->desIP.byte2,
		csv_format->desIP.byte3,
		csv_format->desIP.byte4);

	
	//��������ַ���
	sprintf(result, "%s, %s, %s, %s, %s, %d",
		timestr,
		src_mac_str,
		src_ip_str,
		des_mac_str,
		des_ip_str,
		csv_format->len);

	return result;
}

//����ͳ��
void add_alarm_flow(MAC_add* mac_addr, IP_add* ip_addr, int flow) {
	//��������
	if (GetTickCount64() - last_sec >= 1000) {
		for (int i = 0; i < flow_alarm_list->length; ++i) {
			(flow_alarm_list->HEAD + i)->total = 0;
		}
		last_sec = GetTickCount64();
	}

	//����ͳ��
	bool isFound = false;
	for (int i = 0; i < flow_alarm_list->length; ++i) {
		if (Equal(ip_addr, &(flow_alarm_list->HEAD + i)->IP, mac_addr, &(flow_alarm_list->HEAD + i)->MAC))
		{
			(flow_alarm_list->HEAD + i)->total += flow;
			isFound = true;
		}
	}
	if (!isFound) {
		++(flow_alarm_list->length);
		if ((flow_alarm_list->HEAD = (FLOW_STATEMENT*)realloc(flow_alarm_list->HEAD, (flow_alarm_list->length) * sizeof(FLOW_STATEMENT))) == NULL)
			exit(-1);
		if ((flow_alarm_list->HEAD + flow_alarm_list->length - 1) == NULL)
			exit(-1);
		(flow_alarm_list->HEAD + flow_alarm_list->length - 1)->MAC = *mac_addr;
		(flow_alarm_list->HEAD + flow_alarm_list->length - 1)->IP = *ip_addr;
		(flow_alarm_list->HEAD + flow_alarm_list->length - 1)->total = flow;
	}
}

//����ͳ��
void add_recv_flow(MAC_add* mac_addr, IP_add* ip_addr, int flow) {
	//����ͳ��
	bool isFound = false;
	for (int i = 0; i < flow_recv_list->length; ++i) {
		if (Equal(ip_addr, &(flow_recv_list->HEAD + i)->IP, mac_addr, &(flow_recv_list->HEAD + i)->MAC))
		{
			(flow_recv_list->HEAD + i)->total += flow;
			isFound = true;
		}
	}

	if (!isFound) {
		++(flow_recv_list->length);
		if ((flow_recv_list->HEAD = (FLOW_STATEMENT*)realloc(flow_recv_list->HEAD, (flow_recv_list->length) * sizeof(FLOW_STATEMENT))) == NULL)
			exit(-1);
		if ((flow_recv_list->HEAD + flow_recv_list->length - 1) == NULL)
			exit(-1);
		(flow_recv_list->HEAD + flow_recv_list->length - 1)->MAC = *mac_addr;
		(flow_recv_list->HEAD + flow_recv_list->length - 1)->IP = *ip_addr;
		(flow_recv_list->HEAD + flow_recv_list->length - 1)->total = flow;
	}

	//ͳ�����
	if ((GetTickCount64() - last_recv_output) >= STATISTIC_TIME) {
		printf("\nͳ�����Բ�ͬ MAC �� IP ��ַ��ͨ�����ݳ���:\n");
		for (int i = 0; i < flow_recv_list->length; ++i) {
			printf("MAC��ַ:%02X-%02X-%02X-%02X-%02X-%02X, IP��ַ:%3d:%3d:%3d:%3d, ͨ�����ݳ���:%d\n",
				(flow_recv_list->HEAD + i)->MAC.byte1,
				(flow_recv_list->HEAD + i)->MAC.byte2,
				(flow_recv_list->HEAD + i)->MAC.byte3,
				(flow_recv_list->HEAD + i)->MAC.byte4,
				(flow_recv_list->HEAD + i)->MAC.byte5,
				(flow_recv_list->HEAD + i)->MAC.byte6,
				(flow_recv_list->HEAD + i)->IP.byte1,
				(flow_recv_list->HEAD + i)->IP.byte2,
				(flow_recv_list->HEAD + i)->IP.byte3,
				(flow_recv_list->HEAD + i)->IP.byte4,
				(flow_recv_list->HEAD + i)->total);
		}
		printf("\n\n");
		last_recv_output = GetTickCount64();
	}
}

//����ͳ��
void add_send_flow(MAC_add* mac_addr, IP_add* ip_addr, int flow) {
	//����ͳ��
	bool isFound = false;

	for (int i = 0; i < flow_send_list->length; ++i) {
		if (Equal(ip_addr, &(flow_send_list->HEAD + i)->IP, mac_addr, &(flow_send_list->HEAD + i)->MAC))
		{
			(flow_send_list->HEAD + i)->total += flow;
			isFound = true;
		}

	}

	if (!isFound) {
		++(flow_send_list->length);
		if ((flow_send_list->HEAD = (FLOW_STATEMENT*)realloc(flow_send_list->HEAD, (flow_send_list->length) * sizeof(FLOW_STATEMENT))) == NULL)
			exit(-1);
		if ((flow_send_list->HEAD + flow_send_list->length - 1) == NULL)
			exit(-1);
		(flow_send_list->HEAD + flow_send_list->length - 1)->MAC = *mac_addr;
		(flow_send_list->HEAD + flow_send_list->length - 1)->IP = *ip_addr;
		(flow_send_list->HEAD + flow_send_list->length - 1)->total = flow;
	}



	//ͳ�����
	if ((GetTickCount64() - last_send_output) >= STATISTIC_TIME) {
		printf("\nͳ�Ʒ�����ͬ MAC �� IP ��ַ��ͨ�����ݳ���:\n");
		for (int i = 0; i < flow_send_list->length; ++i) {
			printf("MAC��ַ:%02X-%02X-%02X-%02X-%02X-%02X, IP��ַ:%3d:%3d:%3d:%3d, ͨ�����ݳ���:%d\n",
				(flow_send_list->HEAD + i)->MAC.byte1,
				(flow_send_list->HEAD + i)->MAC.byte2,
				(flow_send_list->HEAD + i)->MAC.byte3,
				(flow_send_list->HEAD + i)->MAC.byte4,
				(flow_send_list->HEAD + i)->MAC.byte5,
				(flow_send_list->HEAD + i)->MAC.byte6,
				(flow_send_list->HEAD + i)->IP.byte1,
				(flow_send_list->HEAD + i)->IP.byte2,
				(flow_send_list->HEAD + i)->IP.byte3,
				(flow_send_list->HEAD + i)->IP.byte4,
				(flow_send_list->HEAD + i)->total);
		}
		printf("\n\n");
		last_send_output = GetTickCount64();
	}
}
/* �������� */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	time_t local_tv_sec;//ʱ��
	//���ڴ��д��CSV������
	struct CSV_FORMAT* csv_format = (struct CSV_FORMAT*)malloc(sizeof(struct CSV_FORMAT));
	//��ȡʱ��
	local_tv_sec = header->ts.tv_sec;
	csv_format->time = localtime(&local_tv_sec);
	//��ȡԴ/Ŀ��IP��MAC��ַ
	csv_format->srcMac = *(MAC_add*)(pkt_data + 0x06);
	csv_format->srcIP = *(IP_add*)(pkt_data + 0x1A);
	csv_format->desMac = *(MAC_add*)(pkt_data);
	csv_format->desIP = *(IP_add*)(pkt_data + 0x1E);
	//��ȡ����
	csv_format->len = header->len;
	//�����ַ���
	CSVFORMAT_to_str(csv_format);
	add_alarm_flow(&csv_format->srcMac, &csv_format->srcIP, csv_format->len);
	add_recv_flow(&csv_format->desMac, &csv_format->desIP, csv_format->len);
	add_send_flow(&csv_format->srcMac, &csv_format->srcIP, csv_format->len);
	char output[100];
	strcpy(output, CSVFORMAT_to_str(csv_format));
	printf("%s\n", output);//�������Ļ
	
	fprintf(fp, "%s\n", output);//������ļ�
}

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;//���
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;//����
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;
	
	//��ʼ������ͳ��
	//���������
	if ((flow_alarm_list = (FLOW_LIST*)malloc(sizeof(FLOW_LIST))) == NULL)
		exit(-1);
	if ((flow_alarm_list->HEAD = (FLOW_STATEMENT*)malloc(sizeof(FLOW_STATEMENT))) == NULL)
		exit(-1);
	flow_alarm_list->length = 0;

	//�������ͱ�
	if ((flow_recv_list = (FLOW_LIST*)malloc(sizeof(FLOW_LIST))) == NULL)
		exit(-1);
	if ((flow_recv_list->HEAD = (FLOW_STATEMENT*)malloc(sizeof(FLOW_STATEMENT))) == NULL)
		exit(-1);
	flow_recv_list->length = 0;

	//�������ձ�
	if ((flow_send_list = (FLOW_LIST*)malloc(sizeof(FLOW_LIST))) == NULL)
		exit(-1);
	if ((flow_send_list->HEAD = (FLOW_STATEMENT*)malloc(sizeof(FLOW_STATEMENT))) == NULL)
		exit(-1);
	flow_send_list->length = 0;

	/* Retrieve the device list *//*�����豸�б�*/
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	/* Print the list *//*��ӡ�б�*/
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	printf("Enter the interface number (1-%d):",i);
	scanf_s("%d", &inum);//ѡ��ӿ�
	/* Check if the user specified a valid adapter *//*����û��Ƿ�ָ������Ч��������*/
	if(inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");
		
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	/* Jump to the selected adapter *//*��ת����ѡ���������*/
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the adapter *//*��������*/
	if ((adhandle= pcap_open_live(d->name,	// name of the device �豸��
							 65536,			// portion of the packet to capture. Ҫ��������ݰ����ֽ���
											// 65536 grants that the whole packet will be captured on all the MACs. 65536����������mac��ַ�ϲ����������ݰ�
							 1,				// promiscuous mode (nonzero means promiscuous)����ģʽ�������ʾ���ӣ����������ڻ���ģʽʱ�������������е������������ݰ���
							 1000,			// read timeout read timeout
							 errbuf			// error buffer ���󻺳���
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/*����Ƿ�����̫�� */
	if(pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	//
	if(d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask=0xffffff; 

	//��������
	if (d->addresses != NULL)//��ǰ�豸��ַ��Ϊ����ȡ����
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else netmask = 0xffffff;//�����豸��C����̫�������У�����Ϊ0xFFFFFF

	//����������ʽ
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	//���ù�����
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr,"\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	//��ʼ����
	//���ļ�
	fp = fopen("csv.txt", "w");
	printf("��ʼ����:%s\n", d->description);
	pcap_freealldevs(alldevs);//�ͷ��豸�б�
	last_sec = GetTickCount64();
	last_recv_output = GetTickCount64();
	last_send_output = GetTickCount64();
	
	pcap_loop(adhandle, 0, packet_handler, NULL);
	fclose(fp);
	return 0;
}

