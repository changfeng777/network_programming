#pragma once

static inline char* XOR(char* buf, size_t len)
{
	for (size_t i = 0; i < len; ++i)
	{
		buf[i] ^= 1;
	}
}

static inline void Decrypt(char* buf, size_t len)
{
	XOR(buf, len);
}

static inline void Encry(char* buf, size_t len)
{
	XOR(buf, len);
}

/*
|============================================|¡¡
|		    send encry	 recv decrypt		 |
|browser---->transfer---->socks5---->server	 |
|											 |
|============================================|

|============================================|¡¡
|			recv decrypt send encry			 |
|browser<----transfer<----socks5<----server	 |
|											 |
|============================================|

*/


