#ifndef _TRANSFER_H_
#define _TRANSFER_H_

#include "common.h"
#include "epoll.h"

class TransferServer : public EpollServer
{
public:
	TransferServer(const char* socks5ServerIp, int socks5ServerPort,  int selfPort = 8000)
		:EpollServer(selfPort)
	{
		memset(&_socks5addr, 0, sizeof(struct sockaddr_in));
		_socks5addr.sin_family = AF_INET;
		_socks5addr.sin_port = htons(socks5ServerPort);
		_socks5addr.sin_addr.s_addr = inet_addr(socks5ServerIp);
	}

	virtual void ConnectEventHandle(int connnectfd);
	virtual void ReadEventHandle(int connectfd);

protected:
	struct sockaddr_in _socks5addr;
};

#endif

