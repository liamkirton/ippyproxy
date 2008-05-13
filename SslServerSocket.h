////////////////////////////////////////////////////////////////////////////////////////////////////
// IpPyProxy
//
// Copyright ©2008 Liam Kirton <liam@int3.ws>
////////////////////////////////////////////////////////////////////////////////////////////////////
// SslServerSocket.h
//
// Created: 15/04/2008
////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma once

////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Socket.h"

////////////////////////////////////////////////////////////////////////////////////////////////////

class SslClientSocket;

class SslServerSocket : public Socket
{
public:
	SslServerSocket(SslClientSocket *sslClientSocket);
public:
	~SslServerSocket();

	Socket *OnAccept(SOCKET hSocket);
	void OnConnect();
	void OnDisconnect();
	void OnReceive(unsigned char *buffer, unsigned int length, unsigned int ip = 0, unsigned short port = 0);
	void OnSendCompletion(DWORD dwNumberOfBytes);

	virtual void Send(unsigned char *buffer, unsigned int length);
	void SendProtocol(unsigned char *buffer, unsigned int length);

protected:
	void InitialiseSsl();
	void InitiateHandshake();
	void ContinueHandshake(unsigned char *buffer, unsigned int length);
	void GetNewClientCredentials();

	void OnHandshakeComplete();

protected:
	SslClientSocket *sslClientSocket_;

	bool bSslHandshakeComplete_;
	
	SCHANNEL_CRED sChannelCred_;
	CredHandle hCreds_;
    CtxtHandle hContext_;

	char *extraBuffer_;
	unsigned int extraBufferLength_;

	Mutex disconnectedSendProtocolQueueMutex_;
	std::map<unsigned char *, unsigned int> disconnectedSendProtocolQueue_;
};

////////////////////////////////////////////////////////////////////////////////////////////////////
