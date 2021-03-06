#ifndef _SOCKS5_H_
#define _SOCKS5_H_

#include "common.h"
#include "epoll.h"

class Socks5Server : public EpollServer
{
public:
	Socks5Server(int port = 8001)
		:EpollServer(port)
	{}

	// 重写虚函数
	virtual void ConnectEventHandle(int connnectfd);
	virtual void ReadEventHandle(int connectfd);

protected:
	// 验证及建立连接
	bool AuthHandle(int connectfd);
	int EstablishmentHandle(int connectfd);
};

#endif

