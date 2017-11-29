#ifndef _EPOLL_H_
#define _EPOLL_H_

#include "common.h"
#include "encrypt.h"

class IgnoreSigPipe
{
 public:
   IgnoreSigPipe()
   {
    	::signal(SIGPIPE, SIG_IGN);
   }
};

static IgnoreSigPipe initObj;

class EpollServer
{
public:

	enum State
	{
		CONNECTED,		// 连接
		AUTH,			// 验证
		ESTABLISHMENT,  // 转发数据
	};

	struct Channel
	{
		int	_fd;			// socket fd
		int _event;			// 事件
		string _buffer;     // 缓冲区

		bool _flag;			// 关闭标志

		Channel()
			:_fd(-1)
			,_event(0)
			,_flag(false)
		{}

		~Channel()
		{
			if(_fd != -1)
			{
				close(_fd);
				TraceDebug("close:%d", _fd);
			}
		}
	};

	struct Connect
	{
		State  _state;			// socks5的状态 Socks5服务器需要，Transfer服务器不需要
		Channel _clientChannel; // 客户端通道
		Channel _serverChannel; // 服务端通道
		int _ref;				// 引用计数

		Connect()
			:_state(CONNECTED)
			,_ref(0)
		{}
	};

	EpollServer(int port)
		:_port(port)
		,_listenfd(-1)
		,_eventfd(-1)
	{}

	virtual ~EpollServer()
	{
		close(_listenfd);
	}

	void SetNoDelay(int fd)
	{
		int optval = 1;
		int ret = ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
			&optval, static_cast<socklen_t>(sizeof optval));
		if(ret != 0)
		{
			ErrorDebug("setsockopt.fd:%d", fd);
		}
	}

	void SetNonblocking(int sfd)
	{
		int flags, s;
		flags = fcntl (sfd, F_GETFL, 0);
		if (flags == -1)
			ErrorDebug("SetNonblocking:F_GETFL");

		flags |= O_NONBLOCK;
		s = fcntl (sfd, F_SETFL, flags);
		if (s == -1)
			ErrorDebug("SetNonblocking:F_SETFL");
	}

	void OpEvent(int fd, int events, int how, int line)
	{
		struct epoll_event event;
		event.events = events;
		event.data.fd = fd;
		if(epoll_ctl(_eventfd, how, fd, &event) == -1)
		{
			ErrorDebug("epoll_ctl.fd:%d+how:%d.line:%d", fd, how, line);
		}
	}

	void RemoveConnect(int fd);
	void SendInLoop(int fd, const char* buf, size_t len);
	void Forwarding(Channel* clientChannel, Channel* serverChannel,
		bool recvDecrypt, bool sendEncry);
	void EventLoop();
	void Start();

	virtual void ConnectEventHandle(int connnectfd) = 0;
	virtual void ReadEventHandle(int connectfd) = 0;
	virtual void WriteEventHandle(int connectfd);

protected:
	int _port;     // 服务端口
	int _listenfd; // 监听套接字

	int	_eventfd;   // 事件描述符 
	static const size_t _MAX_EVENTS; // 最大事件数量

	map<int, Connect*> _connectMap;
};

#endif
