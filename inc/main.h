//
// Created by Sylvain Caussinus on 23/10/2020.
//

#ifndef TRACEROUTE_MAIN_H
#define TRACEROUTE_MAIN_H

#include <iostream>
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <iomanip>
#include <time.h>
#include <signal.h>
#include <sys/time.h>
#include <string>
#include <sys/select.h>

uint16_t	icmpChecksum(uint16_t *data, uint32_t len);
void        hexdumpBuf(char *buf, uint32_t len);
double      getDiffTimeval(const timeval &t1, const timeval &t2);
bool        isEchoReply(uint8_t *buf, ssize_t retRecv);
void        onSignalReceived(int sig);
void        printAddrInfo(addrinfo *pAddrInfo);
void        printSockaddr(sockaddr *sockAddr);
timeval     subTimeval(const timeval &t1, const timeval &t2);
std::string getIpStr(const sockaddr_in &addr);
bool        changeTTL(uint64_t sockFd, uint64_t socketTTL);
bool        sendRequestUDP(uint64_t sockFd, addrinfo *addrInfo);
std::string getDomainName(uint32_t IpAddr, std::string ipAddr);
bool        isTTLExceeded(uint8_t *buf, ssize_t retRecv);

using std::cout;
using std::endl;


#endif //TRACEROUTE_MAIN_H