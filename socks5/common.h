#ifndef _COMMON_H_
#define _COMMON_H_

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

#define __DEBUG__
//#define __TRACE__

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

//���ڵ���׷�ݵ�trace log
inline static void __TraceDebug(const char* filename,int line, const char* function, const char* format, ...)
{
#ifdef __TRACE__
	//������ú�������Ϣ
	fprintf(stdout,"[TRACE][%s:%d:%s]:",GetFileName(filename).c_str(), line, function);

	//����û����trace��Ϣ
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
	//������ú�������Ϣ
	fprintf(stdout,"[ERROR][%s:%d:%s]:",GetFileName(filename).c_str(), line, function);

	//����û����trace��Ϣ
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

#endif // _COMMON_H_