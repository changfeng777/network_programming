#include "socks5.h"

void Socks5Server::ConnectEventHandle(int fd)
{
	Connect* connect = new Connect;
	connect->_state = AUTH;
	connect->_clientChannel._fd = fd;
	connect->_clientChannel._event |= EPOLLIN;
	_connectMap[fd] = connect;
	connect->_ref = 1;

	// 监听读事件
	SetNonblocking(fd);
	SetNoDelay(fd);
	OpEvent(fd, connect->_clientChannel._event, EPOLL_CTL_ADD, __LINE__);
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

	const size_t len = 256;
	char buf[len];

	// 窥探缓冲区是否有足够的数据
	if(recv(connectfd, buf, len, MSG_PEEK) < 3)
		return false;

	int n = recv(connectfd, buf, len, 0);
	if(n < 0)
	{  
		ErrorDebug("read socks5 head");
		return false;
	}

	// 解密
	Decrypt(buf, len);

	if(buf[0] != 0x05)
	{
		ErrorDebug("not socks5 protocol");
		return false;
	}

	// 回复不需要验证
	buf[0] = 0x05;
	buf[1] = 0x0;
	// 加密
	Encry(buf, len);
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

	const size_t len = 256;
	char buf[len];

	// 窥探缓冲区是否有足够的数据，返回0，表示数据还没到
	int rLen = recv(connectfd, buf, len, MSG_PEEK);
	if (rLen <= 0)
	{
		ErrorDebug("read request");
		return -1;
	}

	if (rLen < 10)
		return 0;

	recv(connectfd, buf, 4, 0);

	// 解密
	Decrypt(buf, 4);

	if(buf[0] != 0x05 || buf[2] != 0x0)
	{
		ErrorDebug("not socks5 protocol");
		return -1;
	}

	char ip[16];  // ipv6-16字节 ipv4-4字节
	char port[2]; // 端口

	if(buf[3] == 0x01) // ipv4
	{
		if(recv(connectfd, ip, 4, 0) != 4)
		{
			ErrorDebug("recv ipv4\n");
			return -1;
		}
		ip[4] = '\0';

		// 解密
		Decrypt(ip, 4);
		TraceDebug("ipv4:%s", ip);
	}
	else if(buf[3] == 0x03) //domain name
	{
		if(recv(connectfd, buf, 1, 0) != 1)
		{
			ErrorDebug("read domain name len");
			return -1;
		}

		// 解密
		Decrypt(buf, 1);

		int len = buf[0]; 
		if(recv(connectfd, buf, len, 0) != len)
		{
			ErrorDebug("read domain name");
			return -1;
		}
		buf[len] = '\0';

		// 解密
		Decrypt(buf, len);

		TraceDebug("domain:%s", buf);

		// 通过域名取ip
		struct hostent* hptr = gethostbyname(buf);
		if (hptr == NULL)
		{
			ErrorDebug("gethostbyname(): %s",buf);
			return -1;
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
	if(recv(connectfd, port, 2, 0) != 2)
	{
		ErrorDebug("read port");
		return -1;
	}

	// 解密
	Decrypt(port, 2);

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	memcpy(&addr.sin_addr.s_addr, ip, 4);
	addr.sin_port = *((uint16_t*)port);

	int serverfd = socket(AF_INET, SOCK_STREAM, 0);
	if(serverfd < 0)
	{
		ErrorDebug("socket");
		return -1;
	}

	// connect暂时不能做成异步IO，否则遇到不可访问服务器时，会返回EINPROGRESS。
	// 误以为这个服务器可以连上，给客户端回复可以连接，但是真正向服务send数据时扯淡了。^^
	if (connect(serverfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		switch (errno)
		{
		case EINPROGRESS:
		case EINTR:
		case EISCONN:
			// TraceDebug("connect serverfd:%d, error:%d", serverfd, errno);
			break;
		default:
			ErrorDebug("connect error");
			close(serverfd);
			return -1;
		}
	}

	SetNoDelay(serverfd);
	SetNonblocking(serverfd);

	return serverfd;
}

// socks5 server recv from transfer decrypt
// socks5 server send transfer encry
void Socks5Server::ReadEventHandle(int connectfd)
{	
	TraceDebug("ReadEventHandle %d", connectfd);

	map<int, Connect*>::iterator conIt = _connectMap.find(connectfd);
	if(conIt != _connectMap.end())
	{
		Connect* connect = conIt->second;
		TraceDebug("ReadEventHandle connect:%d", connect->_state);

		if (connect->_state == AUTH)
		{
			if(AuthHandle(connectfd))
				connect->_state = ESTABLISHMENT;
		}
		else if (connect->_state == ESTABLISHMENT)
		{
			// 请求服务器信息，并进行连接
			bool success = true;
			int serverfd = EstablishmentHandle(connectfd);
			if(serverfd > 0)
			{
				// 将serverfd设置为非阻塞，并添加到读事件
				connect->_serverChannel._fd = serverfd;
				connect->_serverChannel._event |= EPOLLIN;

				// 添加serverfd到读事件
				OpEvent(serverfd, connect->_serverChannel._event, EPOLL_CTL_ADD, __LINE__);
				_connectMap[serverfd] = connect;
				connect->_ref++;

				connect->_state = FORWARDING;
			}
			else if (serverfd == -1)
			{
				success = false;
			}
			else if (serverfd == 0)
			{
				return;
			}
			

		  /*+----+-----+-------+------+----------+----------+
			|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
			+----+-----+-------+------+----------+----------+
			| 1  |  1  | X'00' |  1   | Variable |    2     |
			+----+-----+-------+------+----------+----------+*/
			// 定义回复信息
			char reply[10];
			memset(reply, 0, 10);
			reply[0] = 0x05;
			reply[1] = 0x00;
			reply[2] = 0x00;
			reply[3] = 0x01;
			//memcpy(reply+4, ip, 4);
			//memcpy(reply+8, port, 2);

			// 加密发送
			Encry(reply, 10);

			// 回复socks5连接client
			if(send(connectfd, reply, 10, MSG_DONTWAIT) != 10)
			{
				success = false;
				ErrorDebug("reply client error");
			}

			if(success == false)
			{
				RemoveConnect(connectfd);
				if (serverfd > 0)
					RemoveConnect(serverfd);
			}
		}
		else if (connect->_state == FORWARDING)
		{
			// 第一种转发模型：client->sock5 proxy->server
			bool recvDecrypt = true, sendEncry = false;
			Channel* clientChannel = &(connect->_clientChannel);
			Channel* serverChannel = &(connect->_serverChannel);

			// 第二种转发模型:server->sock5 proxy->client 
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
			assert(false);
		}
	}
	else
	{
		ErrorDebug("invalid read connectfd:%d", connectfd);
	}
}

void Usage()
{
	printf("Usage    : socks5_proxy [-lp port]\n");
	printf("Examples : socks5_proxy -lp 8001\n");
	printf("explain	 : -lp: local port\n");
}

int main(int argc, char** argv)
{
	int localPort;
	if (argc == 1)
	{
		localPort = 8001;
	}
	else if(argc != 2)
	{
		Usage();
		exit(-1);
	}
	else
	{
		if(strcmp(argv[5], "-lp"))
		{	
			Usage();
			exit(-1);
		}

		localPort = atoi(argv[6]);
	}

	Socks5Server server(localPort);
	server.Start();
}
