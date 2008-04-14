////////////////////////////////////////////////////////////////////////////////////////////////////
// IpPyProxy
//
// Copyright ©2008 Liam Kirton <liam@int3.ws>
////////////////////////////////////////////////////////////////////////////////////////////////////
// Socket.h
//
// Created: 27/02/2008
////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma once

////////////////////////////////////////////////////////////////////////////////////////////////////

#include "IpPyProxy.h"

#include <map>
#include <vector>

#include "Exceptions.h"
#include "Mutex.h"

////////////////////////////////////////////////////////////////////////////////////////////////////

class Socket
{
public:
	Socket();
protected:
	Socket(SOCKET hSocket);
	virtual ~Socket();

public:
	void AddRef();
	void Release();

	void Connect(unsigned int ip, unsigned short port);
	void Disconnect();
	void Shutdown();

	void Bind(unsigned short port);
	void Listen();
	void Receive();
	virtual void Send(unsigned char *buffer, unsigned int length, unsigned int ip = 0, unsigned short port = 0);

	void OnCompletion(DWORD dwNumberOfBytes, LPOVERLAPPED lpOverlapped);

protected:
	void Initialise();

public:
	virtual Socket *OnAccept(SOCKET hSocket) = 0;
	virtual void OnConnect() = 0;
	virtual void OnDisconnect() = 0;
	virtual void OnReceive(unsigned char *buffer, unsigned int length, unsigned int ip = 0, unsigned short port = 0) = 0;
	virtual void OnSendCompletion(DWORD dwNumberOfBytes) = 0;

private:
	void OnAcceptInternal(DWORD dwNumberOfBytes);
	void OnConnectInternal(DWORD dwNumberOfBytes);
	void OnReceiveInternal(DWORD dwNumberOfBytes);
	void OnSendCompletionInternal(DWORD dwNumberOfBytes);

public:
	LARGE_INTEGER lastActivity_;

protected:
	DWORD dwRefCount_;

	unsigned int ip_;
	unsigned short port_;

	int socketProtocol_;
	int socketType_;

	SOCKET hAcceptSocket_;
	SOCKET hSocket_;
	sockaddr_in sockAddrInAcceptBind_;
	sockaddr_in sockAddrInRecvFrom_;
	int sockAddrInRecvFromSize_;

	bool socketConnected_;

	DWORD dwCompletionKey_;

	WSAOVERLAPPED wsaAcceptOverlapped_;
	WSAOVERLAPPED wsaConnectOverlapped_;
	WSAOVERLAPPED wsaReceiveOverlapped_;

	std::map<unsigned char *, unsigned int> disconnectedSendQueue_;
	std::vector<WSAOVERLAPPED *> wsaSendOverlappedList_;
	Mutex wsaSendOverlappedListMutex_;

	unsigned char *acceptBuffer_;
	DWORD dwAcceptBufferReceived_;

	WSABUF wsaReceiveBuf_;
};

////////////////////////////////////////////////////////////////////////////////////////////////////
