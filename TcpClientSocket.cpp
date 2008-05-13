////////////////////////////////////////////////////////////////////////////////////////////////////
// IpPyProxy
//
// Copyright ©2008 Liam Kirton <liam@int3.ws>
////////////////////////////////////////////////////////////////////////////////////////////////////
// TcpClientSocket.cpp
//
// Created: 27/02/2008
////////////////////////////////////////////////////////////////////////////////////////////////////

#include "TcpClientSocket.h"

#include <iostream>

#include "PyInstance.h"
#include "TcpServerSocket.h"

////////////////////////////////////////////////////////////////////////////////////////////////////

TcpClientSocket::TcpClientSocket() : Socket(),
									 tcpServerSocket_(NULL)
{
	socketProtocol_ = IPPROTO_TCP;
	socketType_ = SOCK_STREAM;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

TcpClientSocket::TcpClientSocket(SOCKET hSocket) : Socket(hSocket),
												   tcpServerSocket_(NULL)
{
	socketProtocol_ = IPPROTO_TCP;
	socketType_ = SOCK_STREAM;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

TcpClientSocket::~TcpClientSocket()
{
	
}

////////////////////////////////////////////////////////////////////////////////////////////////////

Socket *TcpClientSocket::OnAccept(SOCKET hSocket)
{
	TcpClientSocket *acceptSocket = new TcpClientSocket(hSocket);
	acceptSocket->tcpServerSocket_ = new TcpServerSocket(acceptSocket);
	acceptSocket->tcpServerSocket_->AddRef();

	g_SocketsMutex.Lock();
	g_Sockets.push_back(acceptSocket);
	g_Sockets.push_back(acceptSocket->tcpServerSocket_);
	g_SocketsMutex.Unlock();
	
	acceptSocket->tcpServerSocket_->Connect(g_TargetIp, g_TargetPort);
	return acceptSocket;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void TcpClientSocket::OnConnect()
{

}

////////////////////////////////////////////////////////////////////////////////////////////////////

void TcpClientSocket::OnDisconnect()
{
	if(tcpServerSocket_ != NULL)
	{
		tcpServerSocket_->Disconnect();
		tcpServerSocket_->Release();
		tcpServerSocket_ = NULL;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void TcpClientSocket::OnReceive(unsigned char *buffer, unsigned int length, unsigned int ip, unsigned short port)
{
	if(tcpServerSocket_ != NULL)
	{
		unsigned char *modifiedBuffer = NULL;
		unsigned int modifiedBufferLength = 0;

		PyInstance::GetInstance()->ClientRecv(buffer, length, &modifiedBuffer, &modifiedBufferLength);
		if(modifiedBuffer != NULL)
		{
			tcpServerSocket_->Send(modifiedBuffer, modifiedBufferLength);
			delete [] modifiedBuffer;
		}
		else
		{
			tcpServerSocket_->Send(buffer, length);
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void TcpClientSocket::OnSendCompletion(DWORD dwNumberOfBytes)
{
	
}

////////////////////////////////////////////////////////////////////////////////////////////////////
