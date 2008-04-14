////////////////////////////////////////////////////////////////////////////////////////////////////
// IpPyProxy
//
// Copyright ©2008 Liam Kirton <liam@int3.ws>
////////////////////////////////////////////////////////////////////////////////////////////////////
// Socket.cpp
//
// Created: 27/02/2008
////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Socket.h"

#include <iostream>

////////////////////////////////////////////////////////////////////////////////////////////////////

Socket::Socket() : dwRefCount_(1),
				   hAcceptSocket_(INVALID_SOCKET),
				   hSocket_(INVALID_SOCKET),
				   ip_(0),
				   port_(0),
				   socketConnected_(false)
{
	InterlockedIncrement(reinterpret_cast<volatile LONG *>(&g_dwSocketInstanceCount));

	Initialise();
}

////////////////////////////////////////////////////////////////////////////////////////////////////

Socket::Socket(SOCKET hSocket) : dwRefCount_(1),
								 hAcceptSocket_(INVALID_SOCKET),
								 hSocket_(hSocket),
								 ip_(0),
								 port_(0),
								 socketConnected_(false)
{
	InterlockedIncrement(reinterpret_cast<volatile LONG *>(&g_dwSocketInstanceCount));

	Initialise();

	dwCompletionKey_ = reinterpret_cast<DWORD>(this);

	if(CreateIoCompletionPort(reinterpret_cast<HANDLE>(hSocket_),
							  g_hCompletionPort,
							  dwCompletionKey_,
							  0) == NULL)
	{
		throw std::exception("CreateIoCompletionPort(SOCKET) Failed.");
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

Socket::~Socket()
{
	Disconnect();
	
	if(wsaAcceptOverlapped_.hEvent != NULL)
	{
		CloseHandle(wsaAcceptOverlapped_.hEvent);
		wsaAcceptOverlapped_.hEvent = NULL;
	}
	if(wsaConnectOverlapped_.hEvent != NULL)
	{
		CloseHandle(wsaConnectOverlapped_.hEvent);
		wsaConnectOverlapped_.hEvent = NULL;
	}
	if(wsaReceiveOverlapped_.hEvent != NULL)
	{
		CloseHandle(wsaReceiveOverlapped_.hEvent);
		wsaReceiveOverlapped_.hEvent = NULL;
	}
	
	wsaSendOverlappedListMutex_.Lock();
	for(std::map<unsigned char *, unsigned int>::iterator i = disconnectedSendQueue_.begin(); i != disconnectedSendQueue_.end(); ++i)
	{
		delete [] i->first;
	}
	disconnectedSendQueue_.clear();

	for(std::vector<WSAOVERLAPPED *>::iterator i = wsaSendOverlappedList_.begin(); i != wsaSendOverlappedList_.end(); ++i)
	{
		CloseHandle((*i)->hEvent);
		delete (*i);
	}
	wsaSendOverlappedList_.clear();
	wsaSendOverlappedListMutex_.Unlock();

	delete [] acceptBuffer_;
	delete [] wsaReceiveBuf_.buf;

	InterlockedDecrement(reinterpret_cast<volatile LONG *>(&g_dwSocketInstanceCount));
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void Socket::AddRef()
{
	InterlockedIncrement(reinterpret_cast<volatile LONG *>(&dwRefCount_));
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void Socket::Release()
{
	if(InterlockedDecrement(reinterpret_cast<volatile LONG *>(&dwRefCount_)) == 0)
	{
		delete this;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void Socket::Initialise()
{
	SecureZeroMemory(&wsaAcceptOverlapped_, sizeof(WSAOVERLAPPED));
	wsaAcceptOverlapped_.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	SecureZeroMemory(&wsaConnectOverlapped_, sizeof(WSAOVERLAPPED));
	wsaConnectOverlapped_.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	SecureZeroMemory(&wsaReceiveOverlapped_, sizeof(WSAOVERLAPPED));
	wsaReceiveOverlapped_.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	hAcceptSocket_ = INVALID_SOCKET;
	acceptBuffer_ = new unsigned char[128 + (sizeof(sockaddr_in) + 16) * 2];

	wsaReceiveBuf_.len = 1024;
	wsaReceiveBuf_.buf = new char[wsaReceiveBuf_.len];

	SecureZeroMemory(&sockAddrInRecvFrom_, sizeof(sockAddrInRecvFrom_));
	sockAddrInRecvFromSize_ = sizeof(sockAddrInRecvFrom_);

	SecureZeroMemory(&lastActivity_, sizeof(LARGE_INTEGER));
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void Socket::Connect(unsigned int ip, unsigned short port)
{
	Bind(0);

	ip_ = ip;
	port_ = port;

	sockaddr_in sockAddrInConnect;
	SecureZeroMemory(&sockAddrInConnect, sizeof(sockaddr_in));
	sockAddrInConnect.sin_family = AF_INET;
	sockAddrInConnect.sin_port = htons(port_);
	sockAddrInConnect.sin_addr.s_addr = htonl(ip_);

	LPFN_CONNECTEX lpfnConnectEx = NULL;
	GUID guidConnectEx = WSAID_CONNECTEX;

	DWORD cbBytesReturned = 0;
	if(WSAIoctl(hSocket_,
				SIO_GET_EXTENSION_FUNCTION_POINTER,
				&guidConnectEx,
				sizeof(GUID),
				&lpfnConnectEx,
				sizeof(LPFN_CONNECTEX),
				&cbBytesReturned,
				NULL,
				NULL) == SOCKET_ERROR)
	{
		throw std::exception("WSAIoctl Failed.");
	}

	if(lpfnConnectEx(hSocket_,
					 reinterpret_cast<sockaddr *>(&sockAddrInConnect),
					 sizeof(sockaddr_in),
					 NULL,
					 NULL,
					 NULL,
					 &wsaConnectOverlapped_) == FALSE)
	{
		if(WSAGetLastError() != ERROR_IO_PENDING)
		{
			throw std::exception("ConnectEx Failed.");
		}
	}

	QueryPerformanceCounter(&lastActivity_);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void Socket::Disconnect()
{
	if(hSocket_ != NULL)
	{
		Shutdown();
		closesocket(hSocket_);
		CancelIo(reinterpret_cast<HANDLE>(hSocket_));
		hSocket_ = NULL;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void Socket::Shutdown()
{
	if(hSocket_ != NULL)
	{
		shutdown(hSocket_, SD_BOTH);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void Socket::Bind(unsigned short port)
{
	hSocket_ = WSASocket(AF_INET, socketType_, socketProtocol_, NULL, 0, WSA_FLAG_OVERLAPPED);
	if(hSocket_ == INVALID_SOCKET)
	{
		throw std::exception("WSASocket() Failed.");
	}

	sockAddrInAcceptBind_.sin_family = AF_INET;
	sockAddrInAcceptBind_.sin_addr.s_addr = htonl(INADDR_ANY);
	sockAddrInAcceptBind_.sin_port = htons(port);
	
	if(bind(hSocket_,
			reinterpret_cast<sockaddr *>(&sockAddrInAcceptBind_),
			sizeof(sockaddr_in)) == SOCKET_ERROR)
	{
		throw SocketException(this, "bind() Failed.");
	}

	dwCompletionKey_ = reinterpret_cast<DWORD>(this);

	if(CreateIoCompletionPort(reinterpret_cast<HANDLE>(hSocket_),
							  g_hCompletionPort,
							  dwCompletionKey_,
							  0) == NULL)
	{
		throw std::exception("CreateIoCompletionPort(SOCKET) Failed.");
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void Socket::Listen()
{
	if(listen(hSocket_, SOMAXCONN) == SOCKET_ERROR)
	{
		throw SocketException(this, "listen() Failed.");
	}

	AddRef();
	if(!PostQueuedCompletionStatus(g_hCompletionPort, 0, dwCompletionKey_, &wsaAcceptOverlapped_))
	{
		Release();
		throw std::exception("PostQueuedCompletionStatus() Failed.");
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void Socket::Receive()
{
	AddRef();
	if(!PostQueuedCompletionStatus(g_hCompletionPort, 0xFFFFFFFF, dwCompletionKey_, &wsaReceiveOverlapped_))
	{
		Release();
		throw std::exception("PostQueuedCompletionStatus() Failed.");
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void Socket::Send(unsigned char *buffer, unsigned int length, unsigned int ip, unsigned short port)
{
	wsaSendOverlappedListMutex_.Lock();
	if(!socketConnected_)
	{
		unsigned char *queueBuffer = new unsigned char[length];
		RtlCopyMemory(queueBuffer, buffer, length);
		disconnectedSendQueue_[queueBuffer] = length;
		wsaSendOverlappedListMutex_.Unlock();

		buffer = NULL;
		length = 0;
	}
	wsaSendOverlappedListMutex_.Unlock();

	if(buffer != NULL)
	{
		WSABUF wsaSendBuf;
		wsaSendBuf.len = length;
		wsaSendBuf.buf = new char[wsaSendBuf.len];
		RtlCopyMemory(wsaSendBuf.buf, buffer, length);

		DWORD dwNumberOfBytesSent = 0;

		WSAOVERLAPPED *wsaSendOverlapped = new WSAOVERLAPPED;
		SecureZeroMemory(wsaSendOverlapped, sizeof(WSAOVERLAPPED));
		wsaSendOverlapped->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

		wsaSendOverlappedListMutex_.Lock();
		AddRef();
		wsaSendOverlappedList_.push_back(wsaSendOverlapped);
		wsaSendOverlappedListMutex_.Unlock();

		QueryPerformanceCounter(&lastActivity_);

		if(socketType_ == SOCK_STREAM)
		{
			if(WSASend(hSocket_,
					   &wsaSendBuf,
					   1,
					   &dwNumberOfBytesSent,
					   0,
					   wsaSendOverlapped,
					   NULL) == SOCKET_ERROR)
			{
				if(WSAGetLastError() != ERROR_IO_PENDING)
				{
					delete [] wsaSendBuf.buf;
					Release();
					throw SocketDisconnectedException(this, "WSASend() Failed.", WSAGetLastError());
				}
			}
		}
		else
		{
			sockaddr_in sockAddrInSendTo;
			SecureZeroMemory(&sockAddrInSendTo, sizeof(sockAddrInSendTo));
			sockAddrInSendTo.sin_family = AF_INET;
			sockAddrInSendTo.sin_addr.s_addr = htonl(ip);
			sockAddrInSendTo.sin_port = htons(port);

			if(WSASendTo(hSocket_,
						 &wsaSendBuf,
						 1,
						 &dwNumberOfBytesSent,
						 0,
						 reinterpret_cast<const sockaddr *>(&sockAddrInSendTo),
						 sizeof(sockAddrInSendTo),
						 wsaSendOverlapped,
						 NULL) == SOCKET_ERROR)
			{
				if(WSAGetLastError() != ERROR_IO_PENDING)
				{
					delete [] wsaSendBuf.buf;
					Release();
					throw SocketDisconnectedException(this, "WSASendTo() Failed.", WSAGetLastError());
				}
			}
		}
		
		delete [] wsaSendBuf.buf;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void Socket::OnCompletion(DWORD dwNumberOfBytes, LPOVERLAPPED lpOverlapped)
{
	ResetEvent(lpOverlapped->hEvent);

	if(lpOverlapped == &wsaAcceptOverlapped_)
	{
		Release();
		OnAcceptInternal(dwNumberOfBytes);
	}
	else if(lpOverlapped == &wsaConnectOverlapped_)
	{
		OnConnectInternal(dwNumberOfBytes);
	}
	else if(lpOverlapped == &wsaReceiveOverlapped_)
	{
		Release();
		OnReceiveInternal(dwNumberOfBytes);
	}
	else
	{
		bool bCompletion = false;
		wsaSendOverlappedListMutex_.Lock();
		for(std::vector<WSAOVERLAPPED *>::iterator i = wsaSendOverlappedList_.begin(); i != wsaSendOverlappedList_.end(); ++i)
		{
			if((*i) == lpOverlapped)
			{
				bCompletion = true;
				CloseHandle((*i)->hEvent);
				delete (*i);
				wsaSendOverlappedList_.erase(i);
				break;
			}
		}
		wsaSendOverlappedListMutex_.Unlock();

		if(bCompletion)
		{
			Release();
			OnSendCompletionInternal(dwNumberOfBytes);
		}
		else
		{
			EnterCriticalSection(&g_ConsoleCriticalSection);
			std::cout << "[" << reinterpret_cast<DWORD>(this) << "] WARNING: Completion For Unknown Send Overlapped. <" << wsaSendOverlappedList_.size() << ">" << std::endl;
			LeaveCriticalSection(&g_ConsoleCriticalSection);
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void Socket::OnAcceptInternal(DWORD dwNumberOfBytes)
{
	if(hAcceptSocket_ != INVALID_SOCKET)
	{
		SOCKADDR *localSockAddr = NULL;
		SOCKADDR *remoteSockAddr = NULL;
		int localSockAddrLength = 0;
		int remoteSockAddrLength = 0;

		GetAcceptExSockaddrs(acceptBuffer_,
							 128,
							 sizeof(sockaddr_in) + 16,
							 sizeof(sockaddr_in) + 16,
							 &localSockAddr,
							 &localSockAddrLength,
							 &remoteSockAddr,
							 &remoteSockAddrLength);

		if(setsockopt(hAcceptSocket_,
					  SOL_SOCKET,
					  SO_UPDATE_ACCEPT_CONTEXT,
					  reinterpret_cast<char *>(&hSocket_),
					  sizeof(hSocket_)) == SOCKET_ERROR)
		{
			throw SocketDisconnectedException(this, "setsockopt(SO_UPDATE_ACCEPT_CONTEXT) Failed.", WSAGetLastError());
		}

		Socket *acceptSocket = OnAccept(hAcceptSocket_);
		wsaSendOverlappedListMutex_.Lock();
		acceptSocket->socketConnected_ = true;
		for(std::map<unsigned char *, unsigned int>::iterator i = disconnectedSendQueue_.begin(); i != disconnectedSendQueue_.end(); ++i)
		{
			Send(i->first, i->second);
			delete [] i->first;
		}
		disconnectedSendQueue_.clear();
		wsaSendOverlappedListMutex_.Unlock();

		acceptSocket->OnReceive(acceptBuffer_, dwNumberOfBytes);
		acceptSocket->Receive();

		hAcceptSocket_ = INVALID_SOCKET;
	}

	hAcceptSocket_ = WSASocket(AF_INET, socketType_, socketProtocol_, NULL, 0, WSA_FLAG_OVERLAPPED);
	if(hAcceptSocket_ == INVALID_SOCKET)
	{
		throw std::exception("WSASocket() Failed.");
	}

	AddRef();
	if(AcceptEx(hSocket_,
				hAcceptSocket_,
				acceptBuffer_,
				0,
				sizeof(sockaddr_in) + 16,
				sizeof(sockaddr_in) + 16,
				&dwAcceptBufferReceived_,
				&wsaAcceptOverlapped_) == FALSE)
	{
		if(WSAGetLastError() != WSA_IO_PENDING)
		{
			Release();
			throw SocketDisconnectedException(this, "AcceptEx() Failed.", WSAGetLastError());
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void Socket::OnConnectInternal(DWORD dwNumberOfBytes)
{
	if(setsockopt(hSocket_, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) == SOCKET_ERROR)
	{
		EnterCriticalSection(&g_ConsoleCriticalSection);
		std::cout << "Connection Refused." << std::endl;
		LeaveCriticalSection(&g_ConsoleCriticalSection);

		throw SocketDisconnectedException(this, "setsockopt(SO_UPDATE_CONNECT_CONTEXT) Failed.", WSAGetLastError());
	}

	SecureZeroMemory(&lastActivity_, sizeof(LARGE_INTEGER));

	wsaSendOverlappedListMutex_.Lock();
	socketConnected_ = true;
	for(std::map<unsigned char *, unsigned int>::iterator i = disconnectedSendQueue_.begin(); i != disconnectedSendQueue_.end(); ++i)
	{
		Send(i->first, i->second);
		delete [] i->first;
	}
	disconnectedSendQueue_.clear();
	wsaSendOverlappedListMutex_.Unlock();

	OnConnect();
	Receive();
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void Socket::OnReceiveInternal(DWORD dwNumberOfBytes)
{
	if((dwNumberOfBytes == 0) && (socketType_ == SOCK_STREAM))
	{
		throw SocketDisconnectedException(this, "WSARecv() Returned Zero.", 0);
	}
	else if((dwNumberOfBytes > 0) && (dwNumberOfBytes < 0xFFFFFFFF))
	{
		OnReceive(reinterpret_cast<unsigned char *>(wsaReceiveBuf_.buf),
				  dwNumberOfBytes,
				  ntohl(sockAddrInRecvFrom_.sin_addr.s_addr),
				  ntohs(sockAddrInRecvFrom_.sin_port));
	}

	if(hSocket_ == NULL)
	{
		return;
	}
	
	DWORD dwFlags = 0;
	DWORD dwNumberOfBytesRecvd = 0;

	SecureZeroMemory(wsaReceiveBuf_.buf, wsaReceiveBuf_.len);

	QueryPerformanceCounter(&lastActivity_);

	if(socketType_ == SOCK_STREAM)
	{
		AddRef();
		if(WSARecv(hSocket_,
				   &wsaReceiveBuf_,
				   1,
				   &dwNumberOfBytesRecvd,
				   &dwFlags,
				   &wsaReceiveOverlapped_,
				   NULL) == SOCKET_ERROR)
		{
			if(WSAGetLastError() != ERROR_IO_PENDING)
			{
				Release();
				throw SocketDisconnectedException(this, "WSARecv() Failed.", WSAGetLastError());
			}
		}
	}
	else
	{
		AddRef();
		if(WSARecvFrom(hSocket_,
					   &wsaReceiveBuf_,
					   1,
					   &dwNumberOfBytesRecvd,
					   &dwFlags,
					   reinterpret_cast<sockaddr *>(&sockAddrInRecvFrom_),
					   &sockAddrInRecvFromSize_,
					   &wsaReceiveOverlapped_,
					   NULL) == SOCKET_ERROR)
		{
			if(WSAGetLastError() != ERROR_IO_PENDING)
			{
				Release();
				throw SocketDisconnectedException(this, "WSARecvFrom() Failed.", WSAGetLastError());
			}
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void Socket::OnSendCompletionInternal(DWORD dwNumberOfBytes)
{
	OnSendCompletion(dwNumberOfBytes);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
