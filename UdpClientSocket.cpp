////////////////////////////////////////////////////////////////////////////////////////////////////
// IpPyProxy
//
// Copyright �2008 Liam Kirton <liam@int3.ws>
////////////////////////////////////////////////////////////////////////////////////////////////////
// UdpClientSocket.cpp
//
// Created: 15/03/2008
////////////////////////////////////////////////////////////////////////////////////////////////////

#include "UdpClientSocket.h"

#include <iostream>

#include "PyInstance.h"
#include "UdpServerSocket.h"

////////////////////////////////////////////////////////////////////////////////////////////////////

UdpClientSocket::UdpClientSocket() : Socket(),
									 udpServerSocket_(NULL)
{
	socketProtocol_ = IPPROTO_UDP;
	socketType_ = SOCK_DGRAM;
	socketConnected_ = true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

UdpClientSocket::UdpClientSocket(SOCKET hSocket) : Socket(hSocket),
												   udpServerSocket_(NULL)
{
	socketProtocol_ = IPPROTO_UDP;
	socketType_ = SOCK_DGRAM;
	socketConnected_ = true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

UdpClientSocket::~UdpClientSocket()
{
	
}

////////////////////////////////////////////////////////////////////////////////////////////////////

Socket *UdpClientSocket::OnAccept(SOCKET hSocket)
{
	throw new SocketException(this, "Error: UdpClientSocket::OnAccept() Not Supported.");
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void UdpClientSocket::OnConnect()
{
	
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void UdpClientSocket::OnDisconnect()
{
	if(udpServerSocket_ != NULL)
	{
		udpServerSocket_->Disconnect();
		udpServerSocket_->Release();
		udpServerSocket_ = NULL;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void UdpClientSocket::OnReceive(unsigned char *buffer, unsigned int length, unsigned int ip, unsigned short port)
{
	lastIp_ = ip;
	lastPort_ = port;

	if(udpServerSocket_ != NULL)
	{
		unsigned char *modifiedBuffer = NULL;
		unsigned int modifiedBufferLength = 0;

		PyInstance::GetInstance()->UdpClientRecv(buffer, length, &modifiedBuffer, &modifiedBufferLength);
		if(modifiedBuffer != NULL)
		{
			udpServerSocket_->Send(modifiedBuffer, modifiedBufferLength, udpServerSocket_->ip_, udpServerSocket_->port_);
			delete [] modifiedBuffer;
		}
		else
		{
			udpServerSocket_->Send(buffer, length, udpServerSocket_->ip_, udpServerSocket_->port_);
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void UdpClientSocket::OnSendCompletion(DWORD dwNumberOfBytes)
{
	
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void UdpClientSocket::SetUdpServerSocket(UdpServerSocket *udpServerSocket)
{
	udpServerSocket_ = udpServerSocket;
	udpServerSocket_->AddRef();
}

////////////////////////////////////////////////////////////////////////////////////////////////////
