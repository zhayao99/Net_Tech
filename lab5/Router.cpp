#define MAX_BUFF 1000
#include"pcap.h"
#include <WinSock2.h>
#include <Windows.h>
#include <iostream>
#include <stdio.h>
using namespace std;

#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)

#pragma pack (1)//�����ֽڶ��뷽ʽ
//��̫��֡ 14�ֽ�
typedef struct FrameHeader_t {
	BYTE DesMAC[6];	// Ŀ�ĵ�ַ
	BYTE SrcMAC[6];	//Դ��ַ
	WORD FrameType;	//֡����
}FrameHeader_t;
//ARP֡ 28�ֽ�
typedef struct ARPFrame_t {
	FrameHeader_t FrameHeader;//��̫��֡ͷ
	WORD HardwareType;	//Ӳ������
	WORD ProtocolType;	//Э������
	BYTE HLen;			//��ַ����MAC
	BYTE PLen;			//��ַ����IP
	WORD Operation;		//Э�鶯��
	BYTE SendHa[6];		//Դ��ַMAC
	DWORD SendIP;		//Դ��ַIP
	BYTE RecvHa[6];		//Ŀ�ĵ�ַMAC
	DWORD RecvIP;		//Ŀ�ĵ�ַIP
} ARPFrame_t;
//IP�ײ�
typedef struct IPHeader_t {
	BYTE Ver_HLen;		//�汾+ͷ������
	BYTE TOS;           //��������
	WORD TotalLen;		//�ܳ����ֶ�
	WORD ID;			//��ʶ
	WORD Flag_Segment;	//��־+Ƭƫ��
	BYTE TTL;			//��������
	BYTE Protocol;		//Э��
	WORD Checksum;		//У���
	ULONG SrcIP;		//ԴIP
	ULONG DstIP;		//Ŀ��IP
}IPHeader_t;
//����֡�ײ���IP�ײ������ݰ�
typedef struct Data_t {
	FrameHeader_t FrameHeader;	//֡�ײ�
	IPHeader_t IPHeader;		//IP�ײ�
}Data_t;
//����֡�ײ���IP�ײ���ICMP��
typedef struct ICMP {
	FrameHeader_t FrameHeader;	//֡�ײ�
	IPHeader_t IPHeader;		//IP�ײ�
	char buf[40];
}ICMP_t;
#pragma pack ()

//��ӡMAC��ַ
void printMAC(BYTE* MAC) {
	printf("%02x-%02x-%02x-%02x-%02x-%02x", MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);
	return;
}

//ȫ�ֱ���
pcap_if_t* alldevs;
//pcap_t* adhandle;		//��׽ʵ��,��pcap_open���صĶ���
char ipList[10][32];		//�洢�����豸IP��ַ
char maskList[10][32];
int dev_nums = 0;		//��������������
BYTE MyMAC[6];			//�����豸MAC��ַ
//MAC����
bool CompareMAC(BYTE* MAC_1, BYTE* MAC_2) {
	for (int i = 0; i < 6; i++) {
		if (MAC_1[i] != MAC_2[i]) {
			return false;
		}
	}
	return true;
}
void CopyMAC(BYTE* MAC_1, BYTE* MAC_2) {
	for (int i = 0; i < 6; i++) {
		MAC_2[i] = MAC_1[i];
	}
}
//����У���
void setCheckSum(Data_t* dataPacket) {
	dataPacket->IPHeader.Checksum = 0;
	unsigned int sum = 0;
	WORD* t = (WORD*)&dataPacket->IPHeader;//16bitһ��
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++) {
		sum += t[i];
		while (sum >= 0x10000) {
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	dataPacket->IPHeader.Checksum = ~sum;//ȡ��
}
//У��
bool checkCheckSum(Data_t* dataPacket) {
	unsigned int sum = 0;
	WORD* t = (WORD*)&dataPacket->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++) {
		sum += t[i];
		while (sum >= 0x10000) {
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	if (sum == 65535)
		return 1;//У����ȷ
	return 0;
}
//·����Ŀ
class RouteEntry
{
public:
	DWORD destIP;	//Ŀ�ĵ�ַ
	DWORD mask;		//��������
	DWORD nextHop;	//��һ��
	bool fault;		//�Ƿ�ΪĬ��·��
	RouteEntry* nextEntry;	//��ʽ�洢
	RouteEntry() {
		memset(this, 0, sizeof(*this));//��ʼ��Ϊȫ0
		nextEntry = NULL;
	}
	void printEntry()//��ӡ�������ݣ���ӡ�����롢Ŀ���������һ��IP�����ͣ��Ƿ���ֱ��Ͷ�ݣ�
	{
		unsigned char* pIP = (unsigned char*)&destIP;
		printf("Ŀ��IP : %u.%u.%u.%u\t", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));
		pIP = (unsigned char*)&mask;
		printf("�������� : %u.%u.%u.%u\t", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));
		pIP = (unsigned char*)&nextHop;
		printf("��һ��: %u.%u.%u.%u\t", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));
		if (fault) {
			printf("ֱ��Ͷ��\n");
		}
		else {
			printf("��ֱ��Ͷ��\n");
		}
	}
};
//·�ɱ�
class RouteTable
{
public:
	RouteEntry* head;
	int routeNum;//����
	//��ʼ�������ֱ�����ӵ�����
	void initRouteTable() {
		head = NULL;
		routeNum = 0;
		for (int i = 0; i < 2; i++) {
			RouteEntry* newEntry = new RouteEntry();
			newEntry->destIP = (inet_addr(ipList[i])) & (inet_addr(maskList[i]));//����������ip��������а�λ�뼴Ϊ��������
			newEntry->mask = inet_addr(maskList[i]);
			newEntry->fault = 1;//0��ʾֱ��Ͷ�ݵ����磬����ɾ��
			this->addEntry(newEntry);//��ӱ���
		}
	}
	//·�ɱ����ӣ�ֱ��Ͷ������ǰ��ǰ׺������ǰ��
	void addEntry(RouteEntry* newEntry) {
		if (head == NULL) {
			head = newEntry;
			routeNum++;
			return;
		}

		if (newEntry->mask > head->mask) {
			newEntry->nextEntry = head;
			head = newEntry;
			routeNum++;
			return;
		}
		//�������ɳ������ҵ����ʵ�λ��
		RouteEntry* cur = head;
		while (cur->nextEntry) {
			if (newEntry->mask > cur->nextEntry->mask) {
				break;
			}
			cur = cur->nextEntry;
		}
		newEntry->nextEntry = cur->nextEntry;
		cur->nextEntry = newEntry;
		routeNum++;
		return;
	}
	
	bool deleteEntry(DWORD IP) {
		if (IP == head->destIP && !head->fault) {
			delete head;
			head = NULL;
			return true;
		}
		RouteEntry* cur = head;
		while (cur->nextEntry) {
			if (cur->nextEntry->destIP == IP) {
				RouteEntry* temp = cur->nextEntry;
				if (temp->fault) {
					printf("ɾ������·�ɱ���ʧ��!\n");
					return false;
				}
				cur->nextEntry = temp->nextEntry;
				delete temp;
				printf("�ɹ�ɾ��!\n");
				return true;
			}
			cur = cur->nextEntry;
		}
		return false;
	}
	//·�ɱ�Ĵ�ӡ mask net next type
	void printTable() {
		printf("\n--------------------·�ɱ�-------------------------------------------------\n");
		RouteEntry* cur = head;
		while (cur) {
			cur->printEntry();
			cur = cur->nextEntry;
		}
		printf("--------------------------------------------------------------------------------\n\n");
		return;
	}
	//���ң��ǰ׺,������һ����ip
	DWORD lookup(DWORD ip) {
		RouteEntry* cur = head;
		while (cur != NULL) {
			if ((cur->mask & ip) == (cur->mask & cur->destIP)) {
				if (cur->fault) {
					return 0;
				}
				return cur->nextHop;
			}
			cur = cur->nextEntry;
		}
		return -1;
	}
};
//arp��Ŀ
class ArpEntry
{
public:
	DWORD ip;//IP
	BYTE mac[6];//MAC
	void printEntry() {
		unsigned char* pIP = (unsigned char*)&ip;
		printf("IP��ַ: %u.%u.%u.%u \t MAC��ַ: ", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));
		printf("%02x-%02x-%02x-%02x-%02x-%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}
};
//arp��
class ArpTable
{
public:
	ArpEntry arp_table[50];
	ArpTable() {
		arpNum = 0;
	};
	int arpNum = 0;
	void insert(DWORD ip, BYTE mac[6]) {
		for (int i = 0; i < arpNum; i++) {
			if (arp_table[i].ip == ip) {
				CopyMAC(mac, arp_table[i].mac);
				printf("�����Ѿ����ڣ�����!\n");
				return;
			}
		}
		arp_table[arpNum].ip = ip;
		CopyMAC(mac, arp_table[arpNum].mac);
		arpNum++;
		printf("�ɹ�����ARP����!\n");
	}
	int lookup(DWORD ip, BYTE mac[6]) {
		unsigned char* pIP = (unsigned char*)&ip;
		printf("��ARP���в�ѯIP : %u.%u.%u.%u\n", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));
		for (int i = 0; i < arpNum; i++) {
			pIP = (unsigned char*)&arp_table[i].ip;
			if (ip == arp_table[i].ip) {
				CopyMAC(arp_table[i].mac, mac);
				return i;
			}
		}
		printf("ARP�����޸���!\n");
		return -1;
	}
	void printTable() {
		printf("\n---------------------ARP��----------------------\n");
		for (int i = 0; i < arpNum; i++) {
			arp_table[i].printEntry();
		}
		printf("----------------------------------------------------\n\n");
	}
};

RouteTable routeTable;
ArpTable arpTable;

//��־���
void outputLog(Data_t* dataPacket, bool receive) {
	FILE* fp = fopen("myRouter.log", "a");
	if (fp == NULL) {
		printf("���ļ�ʧ�ܣ�\n");
		return;
	}
	DWORD nexthop = routeTable.lookup((DWORD)dataPacket->IPHeader.DstIP);
	unsigned char* SrcIP = (unsigned char*)&dataPacket->IPHeader.SrcIP;
	unsigned char* DstIP = (unsigned char*)&dataPacket->IPHeader.DstIP;
	unsigned char* nextHop = (unsigned char*)&nexthop;
	BYTE* SrcMAC = dataPacket->FrameHeader.SrcMAC;
	BYTE* DstMAC = dataPacket->FrameHeader.DesMAC;

	if (receive) {
		fprintf(fp, "[receive IP] ԴIP��ַ:%u.%u.%u.%u Ŀ��IP��ַ:%u.%u.%u.%u ԴMAC��ַ:%02X-%02X-%02X-%02X-%02X-%02X Ŀ��MAC��ַ:%02X-%02X-%02X-%02X-%02X-%02X\n",
			*SrcIP, *(SrcIP + 1), *(SrcIP + 2), *(SrcIP + 3),
			*DstIP, *(DstIP + 1), *(DstIP + 2), *(DstIP + 3),
			SrcMAC[0], SrcMAC[1], SrcMAC[2], SrcMAC[3], SrcMAC[4], SrcMAC[5],
			DstMAC[0], DstMAC[1], DstMAC[2], DstMAC[3], DstMAC[4], DstMAC[5]);
	}
	else {
		fprintf(fp, "[forward IP] ��һ��:%u.%u.%u.%u ԴMAC��ַ:%02X-%02X-%02X-%02X-%02X-%02X Ŀ��MAC��ַ:%02X-%02X-%02X-%02X-%02X-%02X\n",
			*nextHop, *(nextHop + 1), *(nextHop + 2), *(nextHop + 3),
			SrcMAC[0], SrcMAC[1], SrcMAC[2], SrcMAC[3], SrcMAC[4], SrcMAC[5],
			DstMAC[0], DstMAC[1], DstMAC[2], DstMAC[3], DstMAC[4], DstMAC[5]);
	}
}
//�����ӿ��б�
void DevsInfo(pcap_if_t* alldevs) {
	for (pcap_if_t* d = alldevs; d != nullptr; d = d->next)//��ʾ�ӿ��б�
	{
		//��ȡ������ӿ��豸��ip��ַ��Ϣ
		for (pcap_addr* a = d->addresses; a != nullptr; a = a->next)
		{
			if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr)
			{//��ӡip��ַ
				//��ӡ�����Ϣ
				//inet_ntoa��ip��ַת���ַ�����ʽ
				printf("%d\n", dev_nums);
				printf("%s\t\t%s\n%s\t%s\n", "������:", d->name, "������Ϣ:", d->description);
				printf("%s\t\t%s\n", "IP��ַ:  ", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				printf("%s\t\t%s\n", "��������: ", inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
				printf("-------------------------------------------------------------------------\n");
				strcpy(ipList[dev_nums], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				strcpy(maskList[dev_nums++], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
			}
		}
	}
}
//����ARP��
ARPFrame_t MakeARP() {
	ARPFrame_t ARPFrame;
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;//��ʾ�㲥
	//��APRFrame.FrameHeader.SrcMAC����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.SrcMAC[i] = 0x0f;
	//CopyMAC(ARPFrame.FrameHeader.SrcMAC, MyMAC);
	ARPFrame.FrameHeader.FrameType = htons(0x806);//֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);//Э������ΪIP
	ARPFrame.HLen = 6;//Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4;//Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);//����ΪARP����

	//��ARPFrame.SendHa����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++)
		ARPFrame.SendHa[i] = 0x0f;
	//��ARPFrame.SendIP����Ϊ���������ϰ󶨵�IP��ַ

	//��ARPFrame.RecvHa����Ϊ0
	for (int i = 0; i < 6; i++)
		ARPFrame.RecvHa[i] = 0;//��ʾĿ�ĵ�ַδ֪
	//��ARPFrame.RecvIP����Ϊ�����IP��ַ
	return ARPFrame;
}
//·��ת������
void routeForward(pcap_t* adhandle, ICMP_t data, BYTE DstMAC[]) {
	Data_t* sendPacket = (Data_t*)&data;
	memcpy(sendPacket->FrameHeader.SrcMAC, sendPacket->FrameHeader.DesMAC, 6);	//ԴMACΪ����MAC
	memcpy(sendPacket->FrameHeader.DesMAC, DstMAC, 6);	//Ŀ��MACΪ��һ��MAC
	sendPacket->IPHeader.TTL -= 1;	//����TTL
	if (sendPacket->IPHeader.TTL < 0) {
		printf("TTLʧЧ!\n");
		return;
	}
	setCheckSum(sendPacket);//��������У���
	int res = pcap_sendpacket(adhandle, (const u_char*)sendPacket, 74);//�������ݱ�
	if (res == 0) {
		//���ͳɹ� ��ӡ��־
		outputLog(sendPacket, 0);
		printf("�������ݱ���: ");
		printMAC(DstMAC);
		printf("\n");
	}
}
//��ȡ����MAC��ַ
void getLocalMAC(pcap_if_t* device) {
	int index = 0;
	for (pcap_addr* a = device->addresses; a != nullptr; a = a->next) {
		if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr) {
			//��ӡ����IP��ַ
			printf("%s\t%s\n", "����IP��ַ:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
			//�ڵ�ǰ������α��һ����
			ARPFrame_t ARPFrame = MakeARP();
			ARPFrame.SendIP = inet_addr("0.0.0.0");
			ARPFrame.RecvIP = inet_addr(ipList[index]);
			//�򿪸�����������ӿ�
			pcap_t* adhandle = pcap_open(device->name, 655340, PCAP_OPENFLAG_PROMISCUOUS, 1000, 0, 0);
			if (adhandle == NULL) { printf("�򿪽ӿ�ʧ��!\n"); return; }
			//����ARP��
			int res = pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
			//�������ݰ�
			ARPFrame_t* RecPacket;
			struct pcap_pkthdr* pkt_header;
			const u_char* pkt_data;
			while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
				RecPacket = (ARPFrame_t*)pkt_data;
				if (!CompareMAC(RecPacket->FrameHeader.SrcMAC, ARPFrame.FrameHeader.SrcMAC)
					&& CompareMAC(RecPacket->FrameHeader.DesMAC, ARPFrame.FrameHeader.SrcMAC)
					&& RecPacket->SendIP == ARPFrame.RecvIP
					) { //�������
					CopyMAC(RecPacket->FrameHeader.SrcMAC, MyMAC);//�洢����MAC
					//��ӡ��ȡ��MAC��ַ
					printf("����MAC��ַ: ");
					printMAC(RecPacket->FrameHeader.SrcMAC);
					printf("\n");
					//����ARP��
					arpTable.insert(inet_addr(ipList[index]), RecPacket->FrameHeader.SrcMAC);
					index++;
					break;
				}
			}
		}
	}
}
//��ȡԶ��MAC��ַ
void getRemoteMAC(pcap_if_t* device, DWORD DstIP) {
	int index = 0;
	for (pcap_addr* a = device->addresses; a != nullptr; a = a->next) {
		if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr) {
			DWORD devIP = inet_addr(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
			//ʹ��ͬ���ε�IP����ȡԶ��MAC��ַ
			if ((devIP & inet_addr(maskList[index])) != (DstIP & inet_addr(maskList[index]))) {
				continue;
			}
			//��ӡԶ��IP�ͱ���IP��ַ
			unsigned char* pIP = (unsigned char*)&DstIP;
			printf("Զ��IP��ַ: %u.%u.%u.%u \n", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));
			pIP = (unsigned char*)&devIP;
			printf("����IP��ַ: %u.%u.%u.%u \n", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));
			//�ڵ�ǰ������α��һ����
			ARPFrame_t ARPFrame = MakeARP();
			//����α���ARP�� ��������MAC����
			CopyMAC(MyMAC, ARPFrame.FrameHeader.SrcMAC);
			CopyMAC(MyMAC, ARPFrame.SendHa);
			ARPFrame.SendIP = inet_addr(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
			ARPFrame.RecvIP = DstIP;
			//�򿪸�����������ӿ�
			pcap_t* adhandle = pcap_open(device->name, 655340, PCAP_OPENFLAG_PROMISCUOUS, 1000, 0, 0);
			if (adhandle == NULL) { printf("�򿪽ӿ�ʧ��!\n"); return; }
			//����ARP��
			int res = pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
			//�������ݰ�
			ARPFrame_t* RecPacket;
			struct pcap_pkthdr* pkt_header;
			const u_char* pkt_data;
			while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
				RecPacket = (ARPFrame_t*)pkt_data;
				if (!CompareMAC(RecPacket->FrameHeader.SrcMAC, ARPFrame.FrameHeader.SrcMAC)
					&& CompareMAC(RecPacket->FrameHeader.DesMAC, ARPFrame.FrameHeader.SrcMAC)
					&& RecPacket->SendIP == ARPFrame.RecvIP
					) {	//���˳ɹ�
					//����ARP��
					arpTable.insert(DstIP, RecPacket->FrameHeader.SrcMAC);
					break;
				}
			}
		}
		index++;
		//}
	}
}
//����IP���ݱ�
ICMP CapturePacket(pcap_if_t* device) {
	pcap_t* adhandle = pcap_open(device->name, 655340, PCAP_OPENFLAG_PROMISCUOUS, 1000, 0, 0);
	pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	printf("��ʼ����...\n");
	while (1) {
		int res = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
		if (res > 0) {
			FrameHeader_t* header = (FrameHeader_t*)pkt_data;
			if (CompareMAC(header->DesMAC, MyMAC)) {//��������
				if (ntohs(header->FrameType) == 0x800) {//IP��ʽ�����ݱ�
					Data_t* data = (Data_t*)pkt_data;
					if (!checkCheckSum(data)) {
						printf("У�����!\n");
						continue;
					}
					//��ӡ��־
					outputLog(data, 1);
					//��ȡIP���ݱ��е�Ŀ��IP
					DWORD DstIP = data->IPHeader.DstIP;
					unsigned char* pIP = (unsigned char*)&DstIP;
					//��·�ɱ��в���
					DWORD routeFind = routeTable.lookup(DstIP);
					printf("�ҵ�·�ɵ�ַ: %u.%u.%u.%u \n", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));

					pIP = (unsigned char*)&routeFind;
					printf("��һ��: %u.%u.%u.%u \n", *pIP, *(pIP + 1), *(pIP + 2), *(pIP + 3));

					if (routeFind == -1) {//û�и�·����Ŀ
						printf("û�и�·����Ŀ\n");
						continue;
					}

					printf("�ɹ��ҵ�·�ɱ�\n");
					//����Ƿ�Ϊ�㲥��Ϣ
					BYTE broadcast[6] = "fffff";
					if (!CompareMAC(data->FrameHeader.DesMAC, broadcast)
						&& !CompareMAC(data->FrameHeader.SrcMAC, broadcast)
						)
					{
						//ICMP���İ���IP���ݰ���ͷ����������
						ICMP_t* sendPacket_t = (ICMP_t*)pkt_data;
						ICMP_t sendPacket = *sendPacket_t;
						BYTE mac[6];
						if (routeFind == 0) {
							//Ĭ��·���� ֱ��Ͷ�� ��ARP���в�ѯDstIP
							if (arpTable.lookup(DstIP, mac) == -1) {
								//ARP�����޸���Ŀ ����getRemoteMAC������ȡĿ��IP��MAC��ַ
								printf("��ȡԶ��MAC��ַ!\n");
								getRemoteMAC(device, DstIP);
								//��ӡ���º��ARP��
								arpTable.printTable();
								if (arpTable.lookup(DstIP, mac) == -1) {
									//�Ծ�δ�ҵ�
									printf("�޷����Զ��MAC��ַ!");
									continue;
								}
							}
							printf("Ŀ��MAC��ַ:");
						}
						else {//��Ĭ��·�� ��ȡ��һ����IP��ַ ��ARP���в�ѯnextHop��MAC��ַ
							if (arpTable.lookup(routeFind, mac) == -1) {
								printf("��ȡԶ��MAC��ַ!\n");
								getRemoteMAC(device, routeFind);
								arpTable.printTable();
								if (arpTable.lookup(routeFind, mac) == -1) {
									printf("�޷����Զ��MAC��ַ!");
									continue;
								}
							}
							printf("��һ��MAC��ַ:");
						}
						printMAC(mac);
						printf("\n");
						//����MAC��ַ��ת��IP���ݱ�
						routeForward(adhandle, sendPacket, mac);
					}
				}
			}
		}
	}
}

int main() {

	//pcap_if_t* alldevs;				 //��������������
	char errbuf[PCAP_ERRBUF_SIZE];   //���󻺳���,��СΪ256
	pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf);

	//��ȡ�豸��Ϣ
	DevsInfo(alldevs);
	//��ʼ��·�ɱ���ӡ
	routeTable.initRouteTable();
	routeTable.printTable();
	//��ȡ����MAC��ַ
	getLocalMAC(alldevs);
	//��ӡARP��
	arpTable.printTable();

	//��������
	char control[6];
	char option[6];
	char ipAddress[32];
	char mask[32];
	char nextHop[32];

	printf("> ����ָ��,����:\n");
	printf(">   route [option] [ipAddress] [mask] [nextHop]\n");
	printf(">   arp	  [option]\n");
	printf(">   exit\n");
	while (1) {
		printf("> ");
		scanf("%s", control);
		if (!strcmp(control, "route") || !strcmp(control, "ROUTE"))//����[option]����add, delete, print, start, help
		{
			scanf("%s", option);
			if (!strcmp(option, "add") || !strcmp(option, "ADD")) {
				scanf("%s%s%s", ipAddress, mask, nextHop);
				RouteEntry* newEntry = new RouteEntry;
				newEntry->destIP = inet_addr(ipAddress);
				newEntry->mask = inet_addr(mask);
				newEntry->nextHop = inet_addr(nextHop);
				routeTable.addEntry(newEntry);
				continue;
			}
			else if (!strcmp(option, "delete") || !strcmp(option, "DELETE")) {
				scanf("%s", ipAddress);
				routeTable.deleteEntry(inet_addr(ipAddress));
				continue;
			}
			else if (!strcmp(option, "print") || !strcmp(option, "PRINT")) {
				routeTable.printTable();
				continue;
			}
			else if (!strcmp(option, "start") || !strcmp(option, "START")) {
				CapturePacket(alldevs);
				continue;
			}
			else if (!strcmp(option, "help") || !strcmp(option, "HELP")) {
				printf("����:\n");
				printf(" > route add ip mask nexthop\n");
				printf(" > route delete ip\n");
				printf(" > route start\n");
				printf(" > route print\n");
				continue;
			}
		}
		else if (!strcmp(control, "arp") || !strcmp(control, "ARP")) {
			scanf("%s", option);
			if (!strcmp(option, "show") || !strcmp(option, "SHOW")) {
				arpTable.printTable();
				continue;
			}
		}
		else if (!strcmp(control, "exit") || !strcmp(control, "EXIT")) {
			break;
		}
		printf("����ָ�\n");
	}

	system("pause");

	pcap_freealldevs(alldevs);
}