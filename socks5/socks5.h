#pragma once

#include "epoll.h"

class Socks5Server : public EpollServer
{
public:
	Socks5Server(int port = 8001)
		:EpollServer(port)
	{}

	bool AuthHandle(int connectfd);
	int EstablishmentHandle(int connectfd);

	// 重写虚函数
	virtual void ConnectEventHandle(int connnectfd);
	virtual void ReadEventHandle(int connectfd);
	//virtual void WriteEventHandle(int connectfd);
};