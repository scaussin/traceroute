#include "main.h"

bool isTimeout = false;

int main(int ac, char **av)
{
    if (ac != 2)
    {
        printf("usage: %s address\n", av[0]);
        return 1;
    }

    char *domainNameDest = av[1];

    uint16_t leBonGrosPorc = 33434;

    addrinfo hints = {0};
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_DGRAM; //UDP
    hints.ai_protocol = IPPROTO_UDP;

    //requete DNS pour resoudre le nom de domaine
    addrinfo *addrInfoLst;
    int ret = getaddrinfo(domainNameDest, std::to_string(leBonGrosPorc).c_str(), &hints, &addrInfoLst);
    if (ret)
    {
        cout << "ping: cannot resolve " << domainNameDest << ": Unknown host" << endl;
        return 1;
    }

    //recuperation de l'adresse en char[] pour l'affichage.
    std::string ipDest = getIpStr(*((sockaddr_in *) addrInfoLst->ai_addr));

    addrinfo *addrInfoLstFirst = addrInfoLst;

    if (!addrInfoLstFirst)
    {
        cout << "ERROR return getaddrinfo() empty" << endl;
        return 1;
    }

    if (addrInfoLst->ai_next)
    {
        cout << "traceroute: Warning: " << domainNameDest << " has multiple addresses; using " << ipDest << endl;
    }

    cout << "traceroute to " << domainNameDest << " (" << ipDest << "), ?? hops max, ?? byte packets" << endl;

    printAddrInfo(addrInfoLstFirst);

    //creation de la socket en IPv4 / UDP pour l'envoi des messages
    int sockFdUDP = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockFdUDP == -1)
    {
        cout << "ERROR socket(). impossible to create the socket" << endl;
        return 1;
    }

    //creation de la socket en IPv4 / ICMP pour la reception des messages de response
    int sockFdICMP = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockFdICMP == -1)
    {
        cout << "ERROR socket(). impossible to create the socket" << endl;
        return 1;
    }

    /*cout << "sizeof(sockaddr)" << sizeof(sockaddr) << endl;
    cout << "sizeof(sockaddr*)" << sizeof(sockaddr*) << endl;*/

    sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t) 28001);
    addr.sin_addr.s_addr = INADDR_ANY;

    //MacOs specificity - (uniquement pour send)
    int retBind = bind(sockFdUDP, (sockaddr *) &addr, sizeof(addr));
    if (retBind == -1)
    {
        cout << "retBind error: " << retBind << endl;
    }

    //for recvfrom()
    sockaddr_in sockaddrInRecv = {0};
    fd_set fdRead;

    uint32_t retSelect;
    /*sockaddrInRecv.sin_family = AF_INET;
    sockaddrInRecv.sin_port = 0;
    sockaddrInRecv.sin_addr.s_addr = INADDR_ANY;*/
    char bufRecv[2048] = {0};

    bool loop = true;
    int socketTTL = 1;

    while (loop)
    {
        //modification du TTL
        ret = setsockopt(sockFdUDP, IPPROTO_IP, IP_TTL, &socketTTL, sizeof(socketTTL));
        if (ret == -1)
        {
            perror("perror setsockopt");
            cout << "ret: " << ret << endl << endl;
        }

        cout << std::setw(2) << std::setfill(' ') << socketTTL << "  " << std::flush;
        std::string ipResponseIcmpPrev;
        for (int i = 0; i < 3; i++)
        {
            char sendBuf[32] = {0}; //Ici, Alegay a gagné un BurgerKing 👑
            ssize_t retSend;
            timeval timeSend = {0};
            gettimeofday(&timeSend, nullptr);
            retSend = sendto(sockFdUDP, sendBuf, 32, 0, addrInfoLstFirst->ai_addr, addrInfoLstFirst->ai_addrlen);
            if (retSend == -1)
            {
                cout << "Error sendto()" << endl;
                perror("perror sendto");
                return 1;
            }

            //On incremente le bon gros porc. On cast la structure en sockaddr_in pour changer le port facilement
            ((sockaddr_in *)addrInfoLstFirst->ai_addr)->sin_port = htons((uint16_t) leBonGrosPorc++);

            timeval timeOut = {0};
            timeOut.tv_sec = 5;
            FD_ZERO(&fdRead);
            FD_SET(sockFdICMP, &fdRead);
            //cout << "timeout: " << timeOut.tv_sec << "." << timeOut.tv_usec << endl;
            retSelect = select(sockFdICMP + 1, &fdRead, nullptr, nullptr, &timeOut);
            if (retSelect == -1)
            {
                cout << "Error select()" << endl;
                perror("perror select");
            }
            else if (retSelect == 0)
            {
                cout << " *";
            }
            else
            {
                //data a lire
                socklen_t p = sizeof(sockaddr_in);
                ssize_t retRecv;
                retRecv = recvfrom(sockFdICMP, bufRecv, 2048, 0, (sockaddr *)&sockaddrInRecv, &p);
                if (retRecv == -1)
                {
                    cout << "Error recvfrom()" << endl;
                    perror("perror recvfrom");
                }
                timeval timeRecv = {0};
                gettimeofday(&timeRecv, nullptr);

                std::string ipResponseIcmp = getIpStr(sockaddrInRecv);
                if (!ipResponseIcmpPrev.empty() && ipResponseIcmpPrev != ipResponseIcmp)
                {
                    //l'IP est differente de la precedente
                    cout << endl << "    " << ipResponseIcmp;
                }
                else if (ipResponseIcmpPrev.empty())
                {
                    cout << ipResponseIcmp;
                }

                ipResponseIcmpPrev = ipResponseIcmp;


                cout << "  " << getDiffTimeval(timeSend, timeRecv) << " ms";

                if (ipDest == ipResponseIcmp)
                {
                    loop = false;
                    break;
                }

                //printSockaddr((sockaddr*)&sockaddrInRecv);
                //hexdumpBuf(bufRecv, (uint32_t)retRecv);
            }
        }
        cout << endl;
        socketTTL++;
    }

}

std::string getIpStr(const sockaddr_in &addr)
{
    char tmp[100];
    inet_ntop(addr.sin_family, &(addr.sin_addr), tmp, 100);
    std::string s(tmp);
    return (s);
}

bool isEchoReply(uint8_t *buf, ssize_t retRecv)
{
    ip *ipHeader;
    icmp *icmpHeader;

    if (retRecv >= (long) sizeof(ip))
    {
        ipHeader = (ip *) buf;
        if (ipHeader->ip_p == IPPROTO_ICMP && retRecv >= sizeof(ip) + ipHeader->ip_hl * 4)
        {
            icmpHeader = (icmp *) (buf + ipHeader->ip_hl * 4);
            if (icmpHeader->icmp_type == ICMP_ECHOREPLY && icmpHeader->icmp_code == 0
                && icmpHeader->icmp_hun.ih_idseq.icd_id == (uint16_t) getpid())
            {
                return true;
            }
        }
    }
    return false;
}

timeval subTimeval(const timeval &t1, const timeval &t2)
{
    int64_t diffMicroSec = (t2.tv_sec * 1000000 + t2.tv_usec) - (t1.tv_sec * 1000000 + t1.tv_usec);
    timeval ret = {0};
    ret.tv_sec = diffMicroSec / 1000000;
    ret.tv_usec = diffMicroSec % 1000000;
    return (ret);
}

double getDiffTimeval(const timeval &t1, const timeval &t2)
{
    double ret = (double) (t2.tv_sec * 1000000 + t2.tv_usec) - (double) (t1.tv_sec * 1000000 + t1.tv_usec);
    ret = (ret / 1000);
    return ret;
}

void hexdumpBuf(char *buf, uint32_t len)
{
    for (int i = 0; i < len; i++)
    {
        cout << std::setw(2) << std::setfill('0') << std::hex << (uint16_t) ((uint8_t) buf[i]) << " ";

        if (i % 8 == 7 && i % 16 != 15)
        {
            cout << " ";
        }
        else if (i % 16 == 15)
        {
            cout << endl;
        }
    }
    cout << endl << std::dec;
}

uint16_t icmpChecksum(uint16_t *data, uint32_t len)
{
    uint32_t checksum;

    checksum = 0;
    while (len > 1)
    {
        checksum = checksum + *data++;
        len = len - sizeof(uint16_t);
    }
    if (len)
        checksum = checksum + *(uint8_t *) data;
    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum = checksum + (checksum >> 16);
    return (uint16_t) (~checksum);
}

void printAddrInfo(addrinfo *pAddrInfo)
{
    cout << "ai_flags: " << pAddrInfo->ai_flags << endl;
    cout << "ai_family: " << pAddrInfo->ai_family << endl;
    cout << "ai_socktype: " << pAddrInfo->ai_socktype << endl;
    cout << "ai_protocol: " << pAddrInfo->ai_protocol << endl;
    cout << "ai_addrlen: " << pAddrInfo->ai_addrlen << endl;

    printSockaddr(pAddrInfo->ai_addr);

    if (pAddrInfo->ai_canonname)
    {
        pAddrInfo->ai_canonname[14] = 0;
        cout << "ai_canonname: " << pAddrInfo->ai_canonname << endl << endl;
    }
    cout << endl;
    if (pAddrInfo->ai_next)
        printAddrInfo(pAddrInfo->ai_next);
}

void printSockaddr(sockaddr *sockAddr)
{
    if (sockAddr)
    {
        cout << "ai_addr->sa_len: " << (int) sockAddr->sa_len << endl;
        cout << "ai_addr->sa_family: " << (int) sockAddr->sa_family << endl;
        cout << "ai_addr->sa_data[14]: ";
        for (int d = 0; d < 14; d++)
        {
            cout << std::dec << (int) (uint8_t) sockAddr->sa_data[d] << " ";
        }
        cout << endl;
    }
}