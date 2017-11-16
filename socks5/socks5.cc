#include "socks5.h"


void EpollServer::EventLoop()
{
	// 添加_listenfd读事件
	SetNonblocking(_listenfd);
	SetNoDelay(_listenfd);
	OpEvent(_listenfd, EPOLLIN, EPOLL_CTL_ADD, __LINE__);

	// 事件列表
	struct epoll_event events[_MAX_EVENTS];
	while(1)
	{
		int nfds = epoll_wait(_eventfd, events, _MAX_EVENTS, -1);
		if(nfds == -1)
		{
			ErrorDebug("epoll_wait");
			break;
		}

		for (int i = 0; i < nfds; ++i)
		{
			if (events[i].data.fd == _listenfd)
			{
				// 新连接
				struct sockaddr_in client;  
				socklen_t len = sizeof(client);  
				int newfd = accept(_listenfd,(struct sockaddr*)&client, &len);  
				if(newfd < 0)  
				{  
					ErrorDebug("accept");
					continue;  
				}  

				//TraceDebug("accept new connect:%s:%d",
				//	inet_ntoa(client.sin_addr),ntohs(client.sin_port));  

				// 新连接事件处理
				ConnectEventHandle(newfd);
			}
			else if (events[i].events & (EPOLLIN | EPOLLPRI | EPOLLRDHUP))
			{
				// 读事件
				ReadEventHandle(events[i].data.fd);
			}
			else if(events[i].events & (EPOLLOUT))
			{
				// 读事件
				WriteEventHandle(events[i].data.fd);
			}
			else if(events[i].events & (EPOLLERR))
			{
				// 错误
				ErrorDebug("错误事件：%d", events[i].events);
				break;
			}
			else
			{
				// 未知
				ErrorDebug("未知事件：%d", events[i].events);
				break;
			}
		}
	}
}

void EpollServer::Start()
{	
	_listenfd = socket(PF_INET, SOCK_STREAM, 0);
	if (_listenfd == -1)
	{
		ErrorDebug("socket");
		return;
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(_port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(_listenfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		ErrorDebug("bind");
		return;
	}

	if (listen(_listenfd, 100000) < 0)
	{
		ErrorDebug("listen");
		return;
	}

	TraceDebug("server running on port %d", _port);

	_eventfd = epoll_create(_MAX_EVENTS);
	if (_eventfd == -1)
	{
		ErrorDebug("epoll_create");
		return;
	}

	// 开始事件循环
	EventLoop();
}

/////////////////////////////////////////////////////////////////////////////

void Socks5Server::ConnectEventHandle(int fd)
{
	Connenct* connect = new Connenct;
	connect->_state = CONNECTED;
	connect->_clientChannel._fd = fd;
	connect->_clientChannel._event = EPOLLIN;
	_connectMap[fd] = connect;

	// 监听读事件
	SetNonblocking(fd);
	SetNoDelay(fd);
	OpEvent(fd, EPOLLIN, EPOLL_CTL_ADD, __LINE__);
}

// 授权处理
bool Socks5Server::AuthHandle(int connectfd)
{
/*　+----+----------+----------+
    |VER | NMETHODS | METHODS  |
	+----+----------+----------+
	| 1　| 　　1　　| 1 to 255 |
	+----+----------+----------+

	+----+--------+
	|VER | METHOD |
	+----+--------+
	| 1　| 　1　　|
	+----+--------+*/

	const size_t len = 257;
	char buf[len];
	int n = recv(connectfd, buf, 257, MSG_DONTWAIT);
	if(n < 0)
	{  
		ErrorDebug("read socks5 head");
		return false;
	}

	if(buf[0] != 0x05)
	{
		ErrorDebug("not socks5 protocol");
		return false;
	}

	// 回复不需要验证
	buf[0] = 0x05;
	buf[1] = 0x0;
	if(send(connectfd, buf, 2, MSG_DONTWAIT) != 2)
	{
		ErrorDebug("reply socks5");
		return false;
	}

	return true;
}

int Socks5Server::EstablishmentHandle(int connectfd)
{
	/*　+----+-----+-------+------+----------+----------+
	  |VER | CMD |　RSV　| ATYP | DST.ADDR | DST.PORT |
	  +----+-----+-------+------+----------+----------+
	  | 1　| 　1 | X'00' | 　1　| Variable |　　 2　　|
	  +----+-----+-------+------+----------+----------+*/

	char buf[256];
	if(recv(connectfd, buf, 4, MSG_DONTWAIT) != 4)
	{
		ErrorDebug("read request");
		return -1;
	}

	if(buf[0] != 0x05 || buf[2] != 0x0)
	{
		ErrorDebug("not socks5 protocol");
		return -1;
	}

	char ip[16];  // ipv6-16字节 ipv4-4字节
	char port[2]; // 端口

	if(buf[3] == 0x01) // ipv4
	{
		if(recv(connectfd, ip, 4, MSG_DONTWAIT) != 4)
		{
			ErrorDebug("recv ipv4\n");
			return -1;
		}
		buf[4] = '\0';

		TraceDebug("ipv4:%s", buf);
	}
	else if(buf[3] == 0x03) //domain name
	{
		if(recv(connectfd, buf, 1, MSG_DONTWAIT) != 1)
		{
			ErrorDebug("read domain name len");
			return -1;
		}

		int len = buf[0]; 
		if(recv(connectfd, buf, len, MSG_DONTWAIT) != len)
		{
			ErrorDebug("read domain name");
			return false;
		}
		buf[len] = '\0';

		TraceDebug("domain:%s", buf);

		// 通过域名取ip
		struct hostent* hptr = gethostbyname(buf);
		if (hptr == NULL)
		{
			ErrorDebug("gethostbyname(): %s",buf);
			return false;
		}

		struct in_addr addr;
		memcpy(ip, hptr->h_addr, hptr->h_length);
	}
	else if(buf[3] == 0x04) //ipv6
	{
		ErrorDebug("ipv6 not support");
		return -1;
	}
	else
	{
		ErrorDebug("未知协议");
		return -1;
	}

	// 获取端口
	if(recv(connectfd, port, 2, MSG_DONTWAIT) != 2)
	{
		ErrorDebug("read port");
		return -1;
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	memcpy(&addr.sin_addr.s_addr, ip, 4);
	addr.sin_port = *((uint16_t*)port);

	// 异步连接服务器，避免地址不可访问时的阻塞。
	int serverfd = socket(AF_INET, SOCK_STREAM, 0);
	if(serverfd <= 0)
	{
		ErrorDebug("socket");
		return -1;
	}

	SetNoDelay(serverfd);
	SetNonblocking(serverfd);
	if (connect(serverfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		switch (errno)
		{
		case EINPROGRESS:
		case EINTR:
		case EISCONN:
			break;

		case EAGAIN:
		case EADDRINUSE:
		case EADDRNOTAVAIL:
		case ECONNREFUSED:
		case ENETUNREACH:
			// 需要定时器任务连接重试,当前暂时不好处理
			//retry(serverfd);
			//break;
		default:
			ErrorDebug("connect error");
			close(serverfd);
			serverfd = -1;
		}
	}

	return serverfd;
}

void Socks5Server::ReadEventHandle(int connectfd)
{	
	map<int, Connenct*>::iterator conIt = _connectMap.find(connectfd);
	if(conIt != _connectMap.end())
	{
		Connenct* connect = conIt->second;
		if (connect->_state == CONNECTED)
		{
			if(!AuthHandle(connectfd))
			{
				ErrorDebug("AuthHandle");
				return;
			}

			connect->_state = VERIFYED;
		}
		else if (connect->_state == VERIFYED)
		{
			// 定义回复信息
			char reply[10];
			memset(reply, 0, 10);
			reply[0] = 0x05;
			reply[1] = 0x00;
			reply[2] = 0x00;
			reply[3] = 0x01;

			// 请求服务器信息，并进行连接
			int serverfd = EstablishmentHandle(connectfd);
			if(serverfd > 0)
			{
				// 将serverfd设置为非阻塞，并添加到读事件
				connect->_serverChannel._fd = serverfd;
				connect->_serverChannel._event = EPOLLIN;

				// 添加serverfd到读事件
				OpEvent(serverfd, EPOLLIN, EPOLL_CTL_ADD, __LINE__);
				_connectMap[serverfd] = connect;

				connect->_state = FORWARDING;
			}
			else
			{
				// 若获取失败，则回复连接失败
				reply[1] = 0x04;
			}
			
			// 发送回复信息
			if(send(connectfd, reply, 10, MSG_DONTWAIT) != 10)
			{
				ErrorDebug("reply client error");
			}

			if(reply[1] == 0x04)
			{
				OpEvent(connectfd, 0, EPOLL_CTL_DEL, __LINE__);
				delete _connectMap[connectfd]; 
				_connectMap.erase(connectfd);
			}
		}
		else if (connect->_state == FORWARDING)
		{
			// 第一种转发模型：client->sock5 proxy->server
			Channel* clientChannel = &(connect->_clientChannel);
			Channel* serverChannel = &(connect->_serverChannel);
			int clientfd = connect->_clientChannel._fd;
			int	serverfd = connect->_serverChannel._fd;

			// 第二种转发模型:server->sock5 proxy->client 
			if (serverChannel->_fd == connectfd)
				swap(clientChannel, serverChannel);

			const int bufLen = 4096;
			char buf[bufLen];
			int rLen = recv(clientChannel->_fd, buf, bufLen, 0);
			if(rLen == 0)
			{
				//TraceDebug("recv EOF: %d->%d", clientChannel->_fd, serverChannel->_fd);

				// client收到EOF，shutdown client rd
				//TraceDebug("SHUT_RD:%d", clientChannel->_fd);
				if(clientChannel->_event == EPOLLIN)
				{
					OpEvent(clientChannel->_fd, 0, EPOLL_CTL_DEL, __LINE__);
					clientChannel->_event = 0;
				}
				else
				{
					OpEvent(clientChannel->_fd, clientChannel->_event &= ~EPOLLIN, EPOLL_CTL_MOD, __LINE__);
				}

				//shutdown(clientChannel->_fd, SHUT_RD);
				clientChannel->_flag = true;

				// client收到EOF，shutdown server wr
				if (serverChannel->_buffer.empty())
				{
					shutdown(serverChannel->_fd, SHUT_WR);
					//TraceDebug("SHUT_WR:%d", serverChannel->_fd);
				}
			}
			else if(rLen == -1)
			{
				// 操作被信号中断/超时->连接是正常的
				if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)
				{
					ErrorDebug("recv error:EAGAIN");
				}
				else
				{
					clientChannel->_flag = true;
					ErrorDebug("recv client error");
				}
			}
			else
			{
				//TraceDebug("recv client:%d bytes", rLen);
			}

			// 将接受到的数据转发给另一端
			if(rLen > 0)
			{
				buf[rLen] = '\0';
				SendInLoop(serverChannel->_fd, buf, rLen);
			}

			if (clientChannel->_flag && serverChannel->_flag)
			{
				_connectMap.erase(clientChannel->_fd);
				_connectMap.erase(serverChannel->_fd);
				// 析构Connect时，析构Channel会close fd
				delete connect;
			}
		}
		else
		{
			assert(false);
		}
	}
	else
	{
		ErrorDebug("invalid read connectfd:%d", connectfd);
	}
}

void Socks5Server::SendInLoop(int fd, const char* buf, size_t len)
{
	int sLen = send(fd, buf, len, 0);
	// 如果fd还没完全连接完成，则添加到buffer。
	if(sLen >= 0 || (errno == EWOULDBLOCK || errno == EAGAIN))
	{
		Connenct* connect = _connectMap[fd];
		Channel* channel = &(connect->_clientChannel);

		if (sLen < len)
		{
			if(fd == connect->_serverChannel._fd)
				channel = &(connect->_serverChannel);

			channel->_buffer.append(buf+sLen);

			// 添加写事件
			if(!(channel->_event & EPOLLOUT))
				if(channel->_event == 0)
					OpEvent(fd, channel->_event |= EPOLLOUT, EPOLL_CTL_ADD, __LINE__);
				else
					OpEvent(fd, channel->_event |= EPOLLOUT, EPOLL_CTL_MOD, __LINE__);

			//TraceDebug("send server:%d bytes. left:%d", len-sLen);
		}
		else
		{
			// 写完以后，删除写事件。
			if(channel->_event & EPOLLOUT)
				OpEvent(fd, channel->_event &= ~EPOLLOUT, EPOLL_CTL_MOD, __LINE__);

			//TraceDebug("send server:%d bytes. all", sLen);
		}
	}
	else
	{
		ErrorDebug("send to server:%d", fd);
	}
}

void Socks5Server::WriteEventHandle(int fd)
{
	map<int, Connenct*>::iterator conIt = _connectMap.find(fd);
	if(conIt != _connectMap.end())
	{
		Connenct* connect = conIt->second;
		assert(connect->_state == FORWARDING);
		Channel* channel = &(connect->_clientChannel);
		if(fd == connect->_serverChannel._fd)
			channel = &(connect->_serverChannel);
		
		string buffer = channel->_buffer;
		channel->_buffer.clear();
		SendInLoop(fd, buffer.c_str(), buffer.size());
		//if(sLen >= 0)
		//{
		//	if (sLen < buffer.size())
		//	{
		//		buffer.erase(0, sLen);

		//		// 添加写事件
		//		if(!(channel->_event & EPOLLOUT))
		//			if(channel->_event == 0)
		//				OpEvent(fd, channel->_event |= EPOLLOUT, EPOLL_CTL_ADD, __LINE__);
		//			else
		//				OpEvent(fd, channel->_event |= EPOLLOUT, EPOLL_CTL_MOD, __LINE__);

		//		//TraceDebug("send server:%d bytes. left:%d", buffer.size()-sLen);
		//	}
		//	else
		//	{
		//		// 写完以后，删除写事件。
		//		if(channel->_event & EPOLLOUT)
		//			OpEvent(fd, channel->_event &= ~EPOLLOUT, EPOLL_CTL_MOD, __LINE__);

		//		//TraceDebug("send server:%d bytes. all", sLen);
		//	}
		//}
		//else
		//{
		//	ErrorDebug("send to server:%d.size:%d", fd, buffer.size());
		//}

	}
	else
	{
		ErrorDebug("invalid write fd:%d", fd);
	}
}

int main()
{
	cout<<EAGAIN<<endl;
	cout<<EWOULDBLOCK<<endl;
	cout<<EISCONN<<endl;

	Socks5Server server;
	server.Start();

	return 0;
}