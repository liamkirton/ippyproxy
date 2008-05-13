////////////////////////////////////////////////////////////////////////////////////////////////////
// IpPyProxy
//
// Copyright ©2008 Liam Kirton <liam@int3.ws>
////////////////////////////////////////////////////////////////////////////////////////////////////
// UdpServerSocket.cpp
//
// Created: 15/03/2008
////////////////////////////////////////////////////////////////////////////////////////////////////

#include "UdpServerSocket.h"

#include <iostream>

#include "UdpClientSocket.h"
#include "PyInstance.h"

////////////////////////////////////////////////////////////////////////////////////////////////////

UdpServerSocket::UdpServerSocket(UdpClientSocket *udpClientSocket,
								 unsigned int ip,
								 unsigned short port) : Socket(),
														udpClientSocket_(udpClientSocket),
														ip_(ip),
														port_(port)
{
	udpClientSocket_->AddRef();

	socketProtocol_ = IPPROTO_UDP;
	socketType_ = SOCK_DGRAM;
	socketConnected_ = true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

UdpServerSocket::~UdpServerSocket()
{
	
}

////////////////////////////////////////////////////////////////////////////////////////////////////

Socket *UdpServerSocket::OnAccept(SOCKET hSocket)
{
	throw SocketException(this, "Error: UdpServerSocket::OnAccept() Not Supported.");
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void UdpServerSocket::OnConnect()
{

}

////////////////////////////////////////////////////////////////////////////////////////////////////

void UdpServerSocket::OnDisconnect()
{
	if(udpClientSocket_ != NULL)
	{
		udpClientSocket_->Disconnect();
		udpClientSocket_->Release();
		udpClientSocket_ = NULL;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void UdpServerSocket::OnReceive(unsigned char *buffer, unsigned int length, unsigned int ip, unsigned short port)
{
	if(udpClientSocket_ != NULL)
	{
		unsigned char *modifiedBuffer = NULL;
		unsigned int modifiedBufferLength = 0;

		PyInstance::GetInstance()->ServerRecv(buffer, length, &modifiedBuffer, &modifiedBufferLength);
		if(modifiedBuffer != NULL)
		{
			udpClientSocket_->Send(modifiedBuffer, modifiedBufferLength, udpClientSocket_->lastIp_, udpClientSocket_->lastPort_);
			delete [] modifiedBuffer;
		}
		else
		{
			udpClientSocket_->Send(buffer, length);
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void UdpServerSocket::OnSendCompletion(DWORD dwNumberOfBytes)
{
	
}

////////////////////////////////////////////////////////////////////////////////////////////////////
