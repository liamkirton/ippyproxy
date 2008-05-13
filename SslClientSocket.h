////////////////////////////////////////////////////////////////////////////////////////////////////
// IpPyProxy
//
// Copyright ©2008 Liam Kirton <liam@int3.ws>
////////////////////////////////////////////////////////////////////////////////////////////////////
// SslClientSocket.h
//
// Created: 15/04/2008
////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma once

////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Socket.h"

////////////////////////////////////////////////////////////////////////////////////////////////////

class SslServerSocket;

class SslClientSocket : public Socket
{
public:
	SslClientSocket();
protected:
	SslClientSocket(SOCKET hSocket);
public:
	~SslClientSocket();

	Socket *OnAccept(SOCKET hSocket);
	void OnConnect();
	void OnDisconnect();
	void OnReceive(unsigned char *buffer, unsigned int length, unsigned int ip = 0, unsigned short port = 0);
	void OnSendCompletion(DWORD dwNumberOfBytes);

	virtual void Send(unsigned char *buffer, unsigned int length);
	void SendProtocol(unsigned char *buffer, unsigned int length);

protected:
	void InitialiseSsl();
	void InitiateHandshake(unsigned char *buffer, unsigned int length);
	void ContinueHandshake(unsigned char *buffer, unsigned int length);

	void OnHandshakeComplete();

protected:
	SslServerSocket *sslServerSocket_;

	bool bSslHandshakeInitiated_;
	bool bSslHandshakeComplete_;
	
	HCERTSTORE hMyCertStore_;

	SCHANNEL_CRED sChannelCred_;
	CredHandle hCreds_;
    CtxtHandle hContext_;

	char *extraBuffer_;
	unsigned int extraBufferLength_;

	Mutex disconnectedSendProtocolQueueMutex_;
	std::map<unsigned char *, unsigned int> disconnectedSendProtocolQueue_;
};

////////////////////////////////////////////////////////////////////////////////////////////////////
