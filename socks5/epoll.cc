#include "epoll.h"

const size_t EpollServer::_MAX_EVENTS = 10000;

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

				TraceDebug("accept new connect:%s:%d",
					inet_ntoa(client.sin_addr),ntohs(client.sin_port));  

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
				ErrorDebug("错误事件：%d: %d", events[i].events, i);
				//break;
			}
			else
			{
				// 未知
				ErrorDebug("未知事件：%d", events[i].events);
				//break;
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

void EpollServer::SendInLoop(int fd, const char* buf, size_t len)
{
	int sLen = send(fd, buf, len, 0);
	// 如果fd还没完全连接完成，则添加到buffer。
	if(sLen >= 0 || (errno == EWOULDBLOCK || errno == EAGAIN))
	{
		Connect* connect = _connectMap[fd];
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

void EpollServer::RemoveConnect(int fd)
{
	Connect* connect = _connectMap[fd];
	assert(connect);

	_connectMap.erase(fd);

	if (--connect->_ref == 0)
	{
		delete connect;
	}
}

void EpollServer::Forwarding(Channel* clientChannel, Channel* serverChannel,
							 bool recvDecrypt, bool sendEncry)
{
	const int bufLen = 4096;
	char buf[bufLen];
	int rLen = recv(clientChannel->_fd, buf, bufLen, 0);
	if(rLen > 0)
	{
		if(recvDecrypt)
		{
			Decrypt(buf, rLen);
		}

		//TraceDebug("recv client:%d bytes", rLen);
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
			ErrorDebug("recv client error: %d", clientChannel->_fd);
		}
	}
	else
	{
		// client收到EOF，shutdown client rd
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
		}
	}

	// 将接受到的数据转发给另一端
	if(rLen > 0)
	{
		buf[rLen] = '\0';
		if (sendEncry)
		{
			Encry(buf, rLen);
		}
		
		SendInLoop(serverChannel->_fd, buf, rLen);
	}
}

void EpollServer::WriteEventHandle(int fd)
{
	map<int, Connect*>::iterator conIt = _connectMap.find(fd);
	if(conIt != _connectMap.end())
	{
		Connect* connect = conIt->second;
		assert(connect->_state == ESTABLISHMENT);
		Channel* channel = &(connect->_clientChannel);
		if(fd == connect->_serverChannel._fd)
			channel = &(connect->_serverChannel);

		string buffer = channel->_buffer;
		channel->_buffer.clear();
		SendInLoop(fd, buffer.c_str(), buffer.size());
	}
	else
	{
		ErrorDebug("invalid write fd:%d", fd);
	}
}