#pragma once

#include <iostream>
#include <map>
#include <set>
#include <string>
using namespace std;

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/epoll.h>

#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <unistd.h>
#include <pthread.h>
#include <signal.h>

class IgnoreSigPipe
{
 public:
   IgnoreSigPipe()
   {
    	::signal(SIGPIPE, SIG_IGN);
   }
};

IgnoreSigPipe initObj;

#define __DEBUG__
#define __TRACE__

static string GetFileName(const string& path)
{
	char ch='/';

#ifdef _WIN32
	ch='\\';
#endif

	size_t pos = path.rfind(ch);
	if(pos==string::npos)
		return path;
	else
		return path.substr(pos+ 1);
}
//用于调试追溯的trace log
inline static void __TraceDebug(const char* filename,int line, const char* function, const char* format, ...)
{
#ifdef __TRACE__
	//输出调用函数的信息
	fprintf(stdout,"[%s:%d:%s]:",GetFileName(filename).c_str(), line, function);

	//输出用户打的trace信息
	va_list args;
	va_start(args,format);
	vfprintf(stdout,format, args);
	va_end(args);

	fprintf(stdout,"\n");
#endif
}

inline static void __ErrorDebug(const char* filename,int line, const char* function, const char* format, ...)
{
#ifdef __DEBUG__
	//输出调用函数的信息
	fprintf(stdout,"[%s:%d:%s]:",GetFileName(filename).c_str(), line, function);

	//输出用户打的trace信息
	va_list args;
	va_start(args,format);
	vfprintf(stdout,format, args);
	va_end(args);

	fprintf(stdout," errmsg:%s, errno:%d\n", strerror(errno), errno);
#endif
}

#define TraceDebug(...) \
	__TraceDebug(__FILE__,__LINE__,__FUNCTION__, __VA_ARGS__);

#define ErrorDebug(...) \
	__ErrorDebug(__FILE__,__LINE__,__FUNCTION__, __VA_ARGS__);

class EpollServer
{
public:
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

	void EventLoop();
	void Start();

	virtual void ConnectEventHandle(int connnectfd) = 0;
	virtual void ReadEventHandle(int connectfd) = 0;
	virtual void WriteEventHandle(int connectfd) = 0;

protected:
	int _port;     // 服务端口
	int _listenfd; // 监听套接字

	int	_eventfd;   // 事件描述符 
	static const size_t _MAX_EVENTS; // 最大事件数量
};

const size_t EpollServer::_MAX_EVENTS = 10000;

class Socks5Server : public EpollServer
{
public:
	enum State
	{
		CONNECTED,	  // 连接
		AUTH,	  // 验证
		ESTABLISHMENT,   // 转发数据
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
		State  _state;			// socks5的状态
		Channel _clientChannel; // 客户端通道
		Channel _serverChannel; // 服务端通道
		int _ref;				// 引用计数

		Connect()
			:_state(CONNECTED)
			,_ref(1)
		{}
	};

	Socks5Server(int port = 8000)
		:EpollServer(port)
	{}

	void RemoveConnect(int fd);
	bool AuthHandle(int connectfd);
	int EstablishmentHandle(int connectfd);
	void SendInLoop(int fd, const char* buf, size_t len);
	void Forwarding(Channel* clientChannel, Channel* serverChannel);

	// 重写虚函数
	virtual void ConnectEventHandle(int connnectfd);
	virtual void ReadEventHandle(int connectfd);
	virtual void WriteEventHandle(int connectfd);

protected:
	map<int, Connect*> _connectMap;
};

class TransferServer : public EpollServer
{
public:
	TransferServer(int port = 8000)
		:EpollServer(port)
	{}

	virtual void ReadEventHandle(int connectfd);
	virtual void WriteEventHandle(int connectfd);
};