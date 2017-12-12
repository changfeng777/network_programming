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

// transfer server send to server encry
// transfer server recv from server decrypt
void TransferServer::ReadEventHandle(int connectfd)
{
	map<int, Connect*>::iterator conIt = _connectMap.find(connectfd);
	if(conIt != _connectMap.end())
	{
		bool recvDecrypt = false, sendEncry = true;
		Connect* connect = conIt->second;
		Channel* clientChannel = &(connect->_clientChannel);
		Channel* serverChannel = &(connect->_serverChannel);

		if (serverChannel->_fd == connectfd)
		{
			swap(recvDecrypt, sendEncry);
			swap(clientChannel, serverChannel);
		}

		Forwarding(clientChannel, serverChannel, recvDecrypt, sendEncry);

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

void Usage()
{
	printf("Usage    : transfer_proxy  [-ri ip] [-rp port] [-lp port]\n");
	printf("Examples : transfer_proxy -ri 192.168.1.11 -rp 8000 -lp 8001\n");
	printf("explain	 : -ri: remote ip\n");
	printf("explain	 : -rp: remote port\n");
	printf("explain	 : -lp: local port\n");
}

int main(int argc, char** argv)
{
	const char* remoteIp;
	int remotePort;
	int localPort;
	if (argc == 1)
	{
		//remoteIp = "127.0.0.1";
		remoteIp = "43.224.35.5";
		remotePort = 8001;
		localPort = 8000;
	}
	else if(argc != 7)
	{
		Usage();
		exit(-1);
	}
	else
	{
		if(strcmp(argv[1], "-ri") || strcmp(argv[3], "-rp") || strcmp(argv[5], "-lp"))
		{	
			Usage();
			exit(-1);
		}

		remoteIp = argv[2];
		remotePort = atoi(argv[4]);
		localPort = atoi(argv[6]);
	}

	TransferServer server(remoteIp, remotePort, localPort);
	server.Start();
}

