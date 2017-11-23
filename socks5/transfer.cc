#include "transfer.h"

void TransferServer::ConnectEventHandle(int connnectfd)
{
	int serverfd = socket(AF_INET, SOCK_STREAM, 0);
	if(serverfd < 0)
	{
		ErrorDebug("socket");
		return;
	}

	if (connect(serverfd, (struct sockaddr*)&_socks5addr, sizeof(_socks5addr)) < 0)
	{
		ErrorDebug("connect socks5 server error");
		return;
	}

	Connect* connect = new Connect;
	connect->_clientChannel._fd = connnectfd;
	connect->_clientChannel._event |= EPOLLIN;
	connect->_ref++;
	SetNoDelay(connnectfd);
	SetNonblocking(connnectfd);
	OpEvent(connnectfd, connect->_clientChannel._event, EPOLL_CTL_ADD, __LINE__);

	connect->_serverChannel._fd = serverfd;
	connect->_serverChannel._event  |= EPOLLIN;
	connect->_ref++;
	SetNoDelay(serverfd);
	SetNonblocking(serverfd);
	OpEvent(serverfd, connect->_clientChannel._event, EPOLL_CTL_ADD, __LINE__);

	connect->_state = ESTABLISHMENT;

	_connectMap[connnectfd] = connect;
	_connectMap[serverfd] = connect;
}

void TransferServer::ReadEventHandle(int connectfd)
{
	map<int, Connect*>::iterator conIt = _connectMap.find(connectfd);
	if(conIt != _connectMap.end())
	{
		Connect* connect = conIt->second;
		Channel* clientChannel = &(connect->_clientChannel);
		Channel* serverChannel = &(connect->_serverChannel);
		if (serverChannel->_fd == connectfd)
			swap(clientChannel, serverChannel);

		Forwarding(clientChannel, serverChannel);

		if (clientChannel->_flag && serverChannel->_flag)
		{
			RemoveConnect(clientChannel->_fd);
			RemoveConnect(serverChannel->_fd);
		}
	}
	else
	{
		ErrorDebug("invalid read connectfd:%d", connectfd);
	}
}

int main()
{
	TransferServer server("127.0.0.1", 8001, 8000);
	server.Start();

	return 0;
}