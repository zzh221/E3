#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "pcap.h"
#include <stdbool.h>
#include <time.h>
#define FILTER "ip and udp"
//流量告警0.5M
#define LIMIT 524288
//统计数据长度时间间隔间隔30s
#define STATISTIC_TIME 30000
//包计数
int packet_counter = 0;

int sec = -1;
int min = -1;
//输出文件
FILE* fp=NULL;
//警报间隔计时
ULONGLONG last_sec;
//统计表输出计时
ULONGLONG last_recv_output;
ULONGLONG last_send_output;
//存储记录
char result[100];
/*MAC地址*/
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

/*IP地址*/
typedef struct IP_add{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}IP_add;

/* IPv4 头部*/
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

/* UDP头部*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;
/*tcp 头部*/
typedef struct tcp_header
{
	unsigned short src_port;   //源端口号
	unsigned short dst_port;   //目的端口号
	unsigned int seq_no;    //序列号
	unsigned int ack_no;    //确认号
#if LITTLE_ENDIAN
	unsigned char reserved_1 : 4; //保留6位中的4位首部长度
	unsigned char thl : 4;    //tcp头部长度
	unsigned char flag : 6;    //6位标志
	unsigned char reseverd_2 : 2; //保留6位中的2位
#else
	unsigned char thl : 4;    //tcp头部长度
	unsigned char reserved_1 : 4; //保留6位中的4位首部长度
	unsigned char reseverd_2 : 2; //保留6位中的2位
	unsigned char flag : 6;    //6位标志 
#endif
	unsigned short wnd_size;   //16位窗口大小
	unsigned short chk_sum;   //16位TCP检验和
	unsigned short urgt_p;    //16为紧急指针
}tcp_header;

/*判断IP和Mac地址是否相等*/
bool Equal(IP_add* IP_ADDR_0, IP_add* IP_ADDR_1, MAC_add* MAC_ADDR_0, MAC_add* MAC_ADDR_1) {
	if ((IP_ADDR_0->byte4 == IP_ADDR_1->byte4) && (IP_ADDR_0->byte1 == IP_ADDR_1->byte1) &&
		(IP_ADDR_0->byte2 == IP_ADDR_1->byte2) && (IP_ADDR_0->byte3 == IP_ADDR_1->byte3))
	{
		if ((MAC_ADDR_0->byte6 == MAC_ADDR_1->byte6) && (MAC_ADDR_0->byte1 == MAC_ADDR_1->byte1) &&
			(MAC_ADDR_0->byte2 == MAC_ADDR_1->byte2) && (MAC_ADDR_0->byte3 == MAC_ADDR_1->byte3) &&
			(MAC_ADDR_0->byte4 == MAC_ADDR_1->byte4) && (MAC_ADDR_0->byte5 == MAC_ADDR_1->byte5))
			return true;//相等
		else return false;
	}
	else return false;
}
//流量记录
typedef struct FLOW_STATEMENT {
	MAC_add MAC;		//源/目的MAC地址
	IP_add IP;			//源/目的IP地址
	unsigned total;	//一段时间内的总流量
}FLOW_STATEMENT;


//流量记录表
typedef struct FLOW_LIST {
	FLOW_STATEMENT* HEAD;//表头
	int length;//表长
}FLOW_LIST;

FLOW_LIST* flow_alarm_list;//限制表
FLOW_LIST* flow_recv_list;//受到表
FLOW_LIST* flow_send_list;//发送表
//CSV日志记录内容
typedef struct CSV_FORMAT {
	struct tm* time;	//时间
	MAC_add srcMac;		//源MAC地址
	IP_add srcIP;			//源IP地址
	MAC_add desMac;		//目的MAC地址
	IP_add desIP;			//目的IP地址
	int len;				//帧长度
}CSV_FORMAT;
/*生成用于输出和写入CSV的字符串的函数*/
char* CSVFORMAT_to_str(CSV_FORMAT* csv_format) {

	memset(result, 0, sizeof(result));
	//输出时间
	char timestr[20];
	strftime(timestr, sizeof(timestr), "%Y/%m/%d %H:%M:%S", csv_format->time);

	char src_mac_str[18];//源Mac地址
	char src_ip_str[16]; //源ip地址
	char des_mac_str[18];//目的Mac地址
	char des_ip_str[16]; //目的ip地址

	//输出源MAC地址
	sprintf(src_mac_str, "%02X-%02X-%02X-%02X-%02X-%02X",
		csv_format->srcMac.byte1,
		csv_format->srcMac.byte2,
		csv_format->srcMac.byte3,
		csv_format->srcMac.byte4,
		csv_format->srcMac.byte5,
		csv_format->srcMac.byte6);
	//输出源IP地址
	sprintf(src_ip_str, "%3d:%3d:%3d:%3d",
		csv_format->srcIP.byte1,
		csv_format->srcIP.byte2,
		csv_format->srcIP.byte3,
		csv_format->srcIP.byte4);
	//输出目的MAC地址
	sprintf(des_mac_str, "%02X-%02X-%02X-%02X-%02X-%02X",
		csv_format->desMac.byte1,
		csv_format->desMac.byte2,
		csv_format->desMac.byte3,
		csv_format->desMac.byte4,
		csv_format->desMac.byte5,
		csv_format->desMac.byte6);
	//输出目的IP地址
	sprintf(des_ip_str, "%3d:%3d:%3d:%3d",
		csv_format->desIP.byte1,
		csv_format->desIP.byte2,
		csv_format->desIP.byte3,
		csv_format->desIP.byte4);

	
	//输出完整字符串
	sprintf(result, "%s, %s, %s, %s, %s, %d",
		timestr,
		src_mac_str,
		src_ip_str,
		des_mac_str,
		des_ip_str,
		csv_format->len);

	return result;
}

//流量统计
void add_alarm_flow(MAC_add* mac_addr, IP_add* ip_addr, int flow) {
	//流量重置
	if (GetTickCount64() - last_sec >= 1000) {
		for (int i = 0; i < flow_alarm_list->length; ++i) {
			(flow_alarm_list->HEAD + i)->total = 0;
		}
		last_sec = GetTickCount64();
	}

	//流量统计
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

//接收统计
void add_recv_flow(MAC_add* mac_addr, IP_add* ip_addr, int flow) {
	//流量统计
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

	//统计输出
	if ((GetTickCount64() - last_recv_output) >= STATISTIC_TIME) {
		printf("\n统计来自不同 MAC 和 IP 地址的通信数据长度:\n");
		for (int i = 0; i < flow_recv_list->length; ++i) {
			printf("MAC地址:%02X-%02X-%02X-%02X-%02X-%02X, IP地址:%3d:%3d:%3d:%3d, 通信数据长度:%d\n",
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

//发送统计
void add_send_flow(MAC_add* mac_addr, IP_add* ip_addr, int flow) {
	//流量统计
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



	//统计输出
	if ((GetTickCount64() - last_send_output) >= STATISTIC_TIME) {
		printf("\n统计发至不同 MAC 和 IP 地址的通信数据长度:\n");
		for (int i = 0; i < flow_send_list->length; ++i) {
			printf("MAC地址:%02X-%02X-%02X-%02X-%02X-%02X, IP地址:%3d:%3d:%3d:%3d, 通信数据长度:%d\n",
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
/* 监听函数 */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	time_t local_tv_sec;//时间
	//用于存放写入CSV的数据
	struct CSV_FORMAT* csv_format = (struct CSV_FORMAT*)malloc(sizeof(struct CSV_FORMAT));
	//提取时间
	local_tv_sec = header->ts.tv_sec;
	csv_format->time = localtime(&local_tv_sec);
	//提取源/目的IP与MAC地址
	csv_format->srcMac = *(MAC_add*)(pkt_data + 0x06);
	csv_format->srcIP = *(IP_add*)(pkt_data + 0x1A);
	csv_format->desMac = *(MAC_add*)(pkt_data);
	csv_format->desIP = *(IP_add*)(pkt_data + 0x1E);
	//提取长度
	csv_format->len = header->len;
	//生成字符串
	CSVFORMAT_to_str(csv_format);
	add_alarm_flow(&csv_format->srcMac, &csv_format->srcIP, csv_format->len);
	add_recv_flow(&csv_format->desMac, &csv_format->desIP, csv_format->len);
	add_send_flow(&csv_format->srcMac, &csv_format->srcIP, csv_format->len);
	char output[100];
	strcpy(output, CSVFORMAT_to_str(csv_format));
	printf("%s\n", output);//输出至屏幕
	
	fprintf(fp, "%s\n", output);//输出至文件
}

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;//句柄
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;//掩码
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;
	
	//初始化流量统计
	//流量警告表
	if ((flow_alarm_list = (FLOW_LIST*)malloc(sizeof(FLOW_LIST))) == NULL)
		exit(-1);
	if ((flow_alarm_list->HEAD = (FLOW_STATEMENT*)malloc(sizeof(FLOW_STATEMENT))) == NULL)
		exit(-1);
	flow_alarm_list->length = 0;

	//流量发送表
	if ((flow_recv_list = (FLOW_LIST*)malloc(sizeof(FLOW_LIST))) == NULL)
		exit(-1);
	if ((flow_recv_list->HEAD = (FLOW_STATEMENT*)malloc(sizeof(FLOW_STATEMENT))) == NULL)
		exit(-1);
	flow_recv_list->length = 0;

	//流量接收表
	if ((flow_send_list = (FLOW_LIST*)malloc(sizeof(FLOW_LIST))) == NULL)
		exit(-1);
	if ((flow_send_list->HEAD = (FLOW_STATEMENT*)malloc(sizeof(FLOW_STATEMENT))) == NULL)
		exit(-1);
	flow_send_list->length = 0;

	/* Retrieve the device list *//*检索设备列表*/
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	/* Print the list *//*打印列表*/
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
	scanf_s("%d", &inum);//选择接口
	/* Check if the user specified a valid adapter *//*检查用户是否指定了有效的适配器*/
	if(inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");
		
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	/* Jump to the selected adapter *//*跳转到所选择的适配器*/
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the adapter *//*打开适配器*/
	if ((adhandle= pcap_open_live(d->name,	// name of the device 设备名
							 65536,			// portion of the packet to capture. 要捕获的数据包的字节数
											// 65536 grants that the whole packet will be captured on all the MACs. 65536允许在所有mac地址上捕获整个数据包
							 1,				// promiscuous mode (nonzero means promiscuous)混杂模式（非零表示混杂）当网卡处于混杂模式时，它将接收所有的流经它的数据包。
							 1000,			// read timeout read timeout
							 errbuf			// error buffer 错误缓冲区
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/*检查是否在以太网 */
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

	//设置掩码
	if (d->addresses != NULL)//当前设备地址不为空则取掩码
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else netmask = 0xffffff;//假设设备在C类以太网上运行，掩码为0xFFFFFF

	//检查过滤器格式
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr,"\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	//开始监听
	//打开文件
	fp = fopen("csv.txt", "w");
	printf("开始监听:%s\n", d->description);
	pcap_freealldevs(alldevs);//释放设备列表
	last_sec = GetTickCount64();
	last_recv_output = GetTickCount64();
	last_send_output = GetTickCount64();
	
	pcap_loop(adhandle, 0, packet_handler, NULL);
	fclose(fp);
	return 0;
}

