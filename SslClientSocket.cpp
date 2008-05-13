////////////////////////////////////////////////////////////////////////////////////////////////////
// IpPyProxy
//
// Copyright ©2008 Liam Kirton <liam@int3.ws>
////////////////////////////////////////////////////////////////////////////////////////////////////
// SslClientSocket.cpp
//
// Created: 15/04/2008
////////////////////////////////////////////////////////////////////////////////////////////////////

#include "SslClientSocket.h"

#include <iostream>

#include "PyInstance.h"
#include "SslServerSocket.h"

////////////////////////////////////////////////////////////////////////////////////////////////////

SslClientSocket::SslClientSocket() : Socket(),
									 sslServerSocket_(NULL)
{
	socketProtocol_ = IPPROTO_TCP;
	socketType_ = SOCK_STREAM;

	InitialiseSsl();
}

////////////////////////////////////////////////////////////////////////////////////////////////////

SslClientSocket::SslClientSocket(SOCKET hSocket) : Socket(hSocket),
												   sslServerSocket_(NULL)
{
	socketProtocol_ = IPPROTO_TCP;
	socketType_ = SOCK_STREAM;

	InitialiseSsl();
}

////////////////////////////////////////////////////////////////////////////////////////////////////

SslClientSocket::~SslClientSocket()
{
	DeleteSecurityContext(&hContext_);
	FreeCredentialsHandle(&hCreds_);
	
	if(hMyCertStore_ != NULL)
	{
		CertCloseStore(hMyCertStore_, 0);
		hMyCertStore_ = NULL;
	}

	delete [] extraBuffer_;
	extraBuffer_ = NULL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SslClientSocket::InitialiseSsl()
{
	bSslHandshakeInitiated_ = false;
	bSslHandshakeComplete_ = false;

	SecureZeroMemory(&hCreds_, sizeof(CredHandle));
    SecureZeroMemory(&hContext_, sizeof(CtxtHandle));

	SecureZeroMemory(&sChannelCred_, sizeof(SCHANNEL_CRED));
	sChannelCred_.dwVersion = SCHANNEL_CRED_VERSION;
    sChannelCred_.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
	sChannelCred_.dwMaximumCipherStrength = 0;
	sChannelCred_.grbitEnabledProtocols = 0;

	PCCERT_CONTEXT pCertContext = NULL;

	hMyCertStore_ = CertOpenStore(CERT_STORE_PROV_SYSTEM,
								  X509_ASN_ENCODING,
								  0,
								  CERT_SYSTEM_STORE_LOCAL_MACHINE,
								  L"MY");
	if(hMyCertStore_ == NULL)
	{
		throw SocketException(this, "Error: CertOpenStore() Failed.");
	}

	pCertContext = CertFindCertificateInStore(hMyCertStore_,
											  X509_ASN_ENCODING,
											  0,
											  CERT_FIND_SUBJECT_STR,
											  L"IpPyProxy",
											  NULL);
	if(pCertContext == NULL)
	{
		throw SocketException(this, "Error: CertFindCertificateInStore() Failed.");
	}

	sChannelCred_.cCreds = 1;
	sChannelCred_.paCred = &pCertContext;

	SECURITY_STATUS scRet;
	scRet = AcquireCredentialsHandle(NULL, UNISP_NAME, SECPKG_CRED_INBOUND, NULL, &sChannelCred_, NULL, NULL, &hCreds_, NULL);
	if(scRet != SEC_E_OK)
	{
		throw SocketException(this, "Error: AcquireCredentialsHandle() Failed.");
	}

	if(pCertContext != NULL)
	{
		CertFreeCertificateContext(pCertContext);
		pCertContext = NULL;
	}

	extraBuffer_ = NULL;
	extraBufferLength_ = 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SslClientSocket::InitiateHandshake(unsigned char *buffer, unsigned int length)
{
	DWORD dwSSPIFlags;
    DWORD dwSSPIOutFlags;
    
	dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR |
                  ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

    SecBufferDesc inputBufferDesc;
	SecBuffer inputBuffer;
	inputBufferDesc.ulVersion = SECBUFFER_VERSION;
	inputBufferDesc.cBuffers = 1;
	inputBufferDesc.pBuffers = &inputBuffer;
	inputBuffer.BufferType = SECBUFFER_TOKEN;
	inputBuffer.cbBuffer = length;
	inputBuffer.pvBuffer = buffer;

    SecBufferDesc outputBufferDesc;
	SecBuffer outputBuffer;
	outputBufferDesc.ulVersion = SECBUFFER_VERSION;
	outputBufferDesc.cBuffers = 1;
	outputBufferDesc.pBuffers = &outputBuffer;
	outputBuffer.BufferType = SECBUFFER_TOKEN;
	outputBuffer.cbBuffer = 0;
	outputBuffer.pvBuffer = NULL;

	SECURITY_STATUS scRet = S_OK;
    scRet = AcceptSecurityContext(&hCreds_,
								  NULL,
								  &inputBufferDesc,
								  dwSSPIFlags,
								  SECURITY_NATIVE_DREP,
								  &hContext_,
								  &outputBufferDesc,
								  &dwSSPIOutFlags,
								  NULL);

	if(scRet != SEC_I_CONTINUE_NEEDED)
	{
		throw SocketDisconnectedException(this, "Error: AcceptSecurityContext() Failed.", scRet);
	}

	Send(reinterpret_cast<unsigned char *>(outputBufferDesc.pBuffers[0].pvBuffer), outputBufferDesc.pBuffers[0].cbBuffer);
	FreeContextBuffer(outputBufferDesc.pBuffers[0].pvBuffer);

	bSslHandshakeInitiated_ = true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SslClientSocket::ContinueHandshake(unsigned char *buffer, unsigned int length)
{
	DWORD dwSSPIFlags;
    DWORD dwSSPIOutFlags;
    
    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR |
                  ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

	SecBufferDesc inputBufferDesc;
	SecBuffer inputBuffer[2];

	inputBufferDesc.ulVersion = SECBUFFER_VERSION;
	inputBufferDesc.cBuffers = 2;
	inputBufferDesc.pBuffers = reinterpret_cast<SecBuffer *>(&inputBuffer);

	SecBufferDesc outputBufferDesc;
	SecBuffer outputBuffer;

	outputBufferDesc.ulVersion = SECBUFFER_VERSION;
	outputBufferDesc.cBuffers = 1;
	outputBufferDesc.pBuffers = &outputBuffer;
	outputBuffer.BufferType = SECBUFFER_TOKEN;
	outputBuffer.cbBuffer = 0;
	outputBuffer.pvBuffer = NULL;

	unsigned int recvBufferLength = 0;
	char *recvBuffer = NULL;

	SECURITY_STATUS scRet = SEC_I_CONTINUE_NEEDED;
	while((scRet == SEC_I_CONTINUE_NEEDED) && ((extraBufferLength_ + length) > 0))
	{
		delete [] recvBuffer;
		recvBuffer = NULL;

		recvBufferLength = extraBufferLength_ + length;
		recvBuffer = new char[recvBufferLength];

		if(extraBufferLength_ != 0)
		{
			RtlCopyMemory(recvBuffer, extraBuffer_, extraBufferLength_);
			RtlCopyMemory(recvBuffer + extraBufferLength_, buffer, length);
		}
		else
		{
			RtlCopyMemory(recvBuffer, buffer, length);
		}

		length = 0;
		delete [] extraBuffer_;
		extraBuffer_ = NULL;
		extraBufferLength_ = 0;

		inputBuffer[0].BufferType = SECBUFFER_TOKEN;
		inputBuffer[0].cbBuffer = recvBufferLength;
		inputBuffer[0].pvBuffer = recvBuffer;
		inputBuffer[1].BufferType = SECBUFFER_EMPTY;
		inputBuffer[1].cbBuffer = 0;
		inputBuffer[1].pvBuffer = NULL;
		
		scRet = AcceptSecurityContext(&hCreds_,
									  &hContext_,
									  &inputBufferDesc,
									  dwSSPIFlags,
									  SECURITY_NATIVE_DREP,
									  &hContext_,
									  &outputBufferDesc,
									  &dwSSPIOutFlags,
									  NULL);
		
		if((scRet == SEC_E_OK) ||
		   (scRet == SEC_I_CONTINUE_NEEDED) ||
		   (FAILED(scRet) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR)))
		{
			if((outputBuffer.cbBuffer != 0) && (outputBuffer.pvBuffer != NULL))
			{
				Send(reinterpret_cast<unsigned char *>(outputBufferDesc.pBuffers[0].pvBuffer), outputBufferDesc.pBuffers[0].cbBuffer);
				FreeContextBuffer(outputBufferDesc.pBuffers[0].pvBuffer);
				outputBufferDesc.pBuffers[0].pvBuffer = NULL;
				outputBufferDesc.pBuffers[0].cbBuffer = 0;
			}
		}

		if(scRet == SEC_E_INCOMPLETE_MESSAGE)
		{
			extraBufferLength_ = recvBufferLength;
			extraBuffer_ = new char[extraBufferLength_];
			RtlCopyMemory(extraBuffer_, recvBuffer, recvBufferLength);
			break;
		}
		else
		{
			if((inputBuffer[1].BufferType = SECBUFFER_EXTRA) && (inputBuffer[1].cbBuffer > 0))
			{
				extraBufferLength_ = inputBuffer[1].cbBuffer;
				extraBuffer_ = new char[extraBufferLength_];

				RtlCopyMemory(extraBuffer_, recvBuffer + recvBufferLength - inputBuffer[1].cbBuffer, inputBuffer[1].cbBuffer);
			}
		
			if(scRet == SEC_E_OK)
			{
				bSslHandshakeComplete_ = true;
				OnHandshakeComplete();
				break;
			}
			else if(FAILED(scRet))
			{
				throw SocketDisconnectedException(this, "Error: AcceptSecurityContext() Failed.", scRet);
			}
		}

		break;
	}

	delete [] recvBuffer;
	recvBuffer = NULL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SslClientSocket::Send(unsigned char *buffer, unsigned int length)
{
	if(!bSslHandshakeComplete_)
	{
		Socket::Send(buffer, length, 0, 0);
		return;
	}

	SecPkgContext_StreamSizes streamSizes;
	SECURITY_STATUS scRet;
    if((scRet = QueryContextAttributes(&hContext_, SECPKG_ATTR_STREAM_SIZES, &streamSizes)) != SEC_E_OK)
    {
		throw SocketDisconnectedException(this, "Error: QueryContextAttributes() Failed.", scRet);
    }
	else if(streamSizes.cbMaximumMessage < length)
	{
		throw SocketDisconnectedException(this, "Error: SslClientSocket::Send() - Buffer Too Large.", -1);
	}

	DWORD dwSendBufferSize = length + streamSizes.cbHeader + streamSizes.cbTrailer;
	unsigned char *sendBuffer = new unsigned char[dwSendBufferSize];
	SecureZeroMemory(sendBuffer, dwSendBufferSize);

	RtlCopyMemory(sendBuffer + streamSizes.cbHeader, buffer, length);

	SecBufferDesc secBufferDesc;
	SecBuffer secBuffer[4];

	secBufferDesc.ulVersion = SECBUFFER_VERSION;
	secBufferDesc.cBuffers = 4;
	secBufferDesc.pBuffers = reinterpret_cast<SecBuffer *>(&secBuffer);

	secBuffer[0].BufferType = SECBUFFER_STREAM_HEADER;
	secBuffer[0].cbBuffer = streamSizes.cbHeader;
	secBuffer[0].pvBuffer = sendBuffer;
	secBuffer[1].BufferType = SECBUFFER_DATA;
	secBuffer[1].cbBuffer = length;
	secBuffer[1].pvBuffer = sendBuffer + streamSizes.cbHeader;
	secBuffer[2].BufferType = SECBUFFER_STREAM_TRAILER;
	secBuffer[2].cbBuffer = streamSizes.cbTrailer;
	secBuffer[2].pvBuffer = sendBuffer + streamSizes.cbHeader + length;
	secBuffer[3].BufferType = SECBUFFER_EMPTY;
	secBuffer[3].cbBuffer = 0;
	secBuffer[3].pvBuffer = NULL;

	scRet = EncryptMessage(&hContext_, 0, &secBufferDesc, 0);
	if(scRet != SEC_E_OK)
	{
		throw SocketDisconnectedException(this, "Error: EncryptMessage() Failed.", scRet);
	}

	Socket::Send(sendBuffer, secBuffer[0].cbBuffer + secBuffer[1].cbBuffer + secBuffer[2].cbBuffer);
	
	delete [] sendBuffer;
	sendBuffer = NULL;	
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SslClientSocket::SendProtocol(unsigned char *buffer, unsigned int length)
{
	if(!bSslHandshakeComplete_)
	{
		disconnectedSendProtocolQueueMutex_.Lock();

		unsigned char *queueBuffer = new unsigned char[length];
		RtlCopyMemory(queueBuffer, buffer, length);
		disconnectedSendProtocolQueue_[queueBuffer] = length;
		wsaSendOverlappedListMutex_.Unlock();

		disconnectedSendProtocolQueueMutex_.Unlock();
	}
	else
	{
		Send(buffer, length);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

Socket *SslClientSocket::OnAccept(SOCKET hSocket)
{
	SslClientSocket *acceptSocket = new SslClientSocket(hSocket);
	acceptSocket->InitialiseSsl();

	acceptSocket->sslServerSocket_ = new SslServerSocket(acceptSocket);
	acceptSocket->sslServerSocket_->AddRef();

	g_SocketsMutex.Lock();
	g_Sockets.push_back(acceptSocket);
	g_Sockets.push_back(acceptSocket->sslServerSocket_);
	g_SocketsMutex.Unlock();
	
	acceptSocket->sslServerSocket_->Connect(g_TargetIp, g_TargetPort);
	return acceptSocket;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SslClientSocket::OnConnect()
{
	
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SslClientSocket::OnDisconnect()
{
	if(sslServerSocket_ != NULL)
	{
		sslServerSocket_->Disconnect();
		sslServerSocket_->Release();
		sslServerSocket_ = NULL;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SslClientSocket::OnHandshakeComplete()
{
	disconnectedSendProtocolQueueMutex_.Lock();
	for(std::map<unsigned char *, unsigned int>::iterator i = disconnectedSendProtocolQueue_.begin(); i != disconnectedSendProtocolQueue_.end(); ++i)
	{
		SendProtocol(i->first, i->second);
		delete [] i->first;
	}
	disconnectedSendProtocolQueue_.clear();
	disconnectedSendProtocolQueueMutex_.Unlock();
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SslClientSocket::OnReceive(unsigned char *buffer, unsigned int length, unsigned int ip, unsigned short port)
{
	if(!bSslHandshakeComplete_)
	{
		if(length > 0)
		{
			if(!bSslHandshakeInitiated_)
			{
				InitiateHandshake(buffer, length);
			}
			else
			{
				ContinueHandshake(buffer, length);
			}
		}
		return;
	}

	SecBufferDesc secBufferDesc;
	SecBuffer secBuffer[4];

	secBufferDesc.ulVersion = SECBUFFER_VERSION;
	secBufferDesc.cBuffers = 4;
	secBufferDesc.pBuffers = reinterpret_cast<SecBuffer *>(&secBuffer);

	char *recvBuffer = NULL;

	while((extraBufferLength_ + length) > 0)
	{
		delete [] recvBuffer;
		recvBuffer = NULL;

		unsigned int recvBufferLength = extraBufferLength_ + length;
		recvBuffer = new char[recvBufferLength];

		if(extraBufferLength_ != 0)
		{
			RtlCopyMemory(recvBuffer, extraBuffer_, extraBufferLength_);
			RtlCopyMemory(recvBuffer + extraBufferLength_, buffer, length);
		}
		else
		{
			RtlCopyMemory(recvBuffer, buffer, length);
		}
		
		secBuffer[0].BufferType = SECBUFFER_DATA;
		secBuffer[0].cbBuffer = recvBufferLength;
		secBuffer[0].pvBuffer = recvBuffer;
		secBuffer[1].BufferType = SECBUFFER_EMPTY;
		secBuffer[1].cbBuffer = 0;
		secBuffer[1].pvBuffer = NULL;
		secBuffer[2].BufferType = SECBUFFER_EMPTY;
		secBuffer[2].cbBuffer = 0;
		secBuffer[2].pvBuffer = NULL;
		secBuffer[3].BufferType = SECBUFFER_EMPTY;
		secBuffer[3].cbBuffer = 0;
		secBuffer[3].pvBuffer = NULL;

		SECURITY_STATUS scRet = DecryptMessage(&hContext_, &secBufferDesc, 0, NULL);
		if(scRet == SEC_E_INCOMPLETE_MESSAGE)
		{
			break;
		}
		else
		{
			delete [] extraBuffer_;
			extraBuffer_ = NULL;
			extraBufferLength_ = 0;

			length = 0;

			for(DWORD i = 1; i < 4; ++i)
			{
				if(secBuffer[i].BufferType == SECBUFFER_DATA)
				{
					if(sslServerSocket_ != NULL)
					{
						unsigned char *modifiedBuffer = NULL;
						unsigned int modifiedBufferLength = 0;

						PyInstance::GetInstance()->ClientRecv(reinterpret_cast<const unsigned char *>(secBuffer[i].pvBuffer),
													 		  secBuffer[i].cbBuffer,
															  &modifiedBuffer,
															  &modifiedBufferLength);
						if(modifiedBuffer != NULL)
						{
							sslServerSocket_->SendProtocol(modifiedBuffer, modifiedBufferLength);
							delete [] modifiedBuffer;
						}
						else
						{
							sslServerSocket_->SendProtocol(reinterpret_cast<unsigned char *>(secBuffer[i].pvBuffer),
														   secBuffer[i].cbBuffer);
						}
					}
				}
				else if(secBuffer[i].BufferType == SECBUFFER_EXTRA)
				{
					extraBufferLength_ = secBuffer[i].cbBuffer;
					extraBuffer_ = new char[extraBufferLength_];

					RtlCopyMemory(extraBuffer_, secBuffer[i].pvBuffer, extraBufferLength_);
				}
			}

			if(scRet == SEC_I_CONTEXT_EXPIRED)
			{
				delete [] recvBuffer;
				recvBuffer = NULL;
				throw SocketDisconnectedException(this, "Error: DecryptMessage() Returned SEC_I_CONTEXT_EXPIRED.", scRet);
			}
		}
	}

	delete [] recvBuffer;
	recvBuffer = NULL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SslClientSocket::OnSendCompletion(DWORD dwNumberOfBytes)
{
	
}

////////////////////////////////////////////////////////////////////////////////////////////////////
