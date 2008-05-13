////////////////////////////////////////////////////////////////////////////////////////////////////
// IpPyProxy
//
// Copyright ©2008 Liam Kirton <liam@int3.ws>
////////////////////////////////////////////////////////////////////////////////////////////////////
// SslServerSocket.cpp
//
// Created: 15/04/2008
////////////////////////////////////////////////////////////////////////////////////////////////////

#include "SslServerSocket.h"

#include <iostream>

#include "PyInstance.h"
#include "SslClientSocket.h"

////////////////////////////////////////////////////////////////////////////////////////////////////

SslServerSocket::SslServerSocket(SslClientSocket *sslClientSocket) : Socket(),
																	 sslClientSocket_(sslClientSocket)
{
	sslClientSocket_->AddRef();

	socketProtocol_ = IPPROTO_TCP;
	socketType_ = SOCK_STREAM;

	InitialiseSsl();
}

////////////////////////////////////////////////////////////////////////////////////////////////////

SslServerSocket::~SslServerSocket()
{
	DeleteSecurityContext(&hContext_);
	FreeCredentialsHandle(&hCreds_);
	
	delete [] extraBuffer_;
	extraBuffer_ = NULL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SslServerSocket::InitialiseSsl()
{
	bSslHandshakeComplete_ = false;

	SecureZeroMemory(&hCreds_, sizeof(CredHandle));
    SecureZeroMemory(&hContext_, sizeof(CtxtHandle));

	SecureZeroMemory(&sChannelCred_, sizeof(SCHANNEL_CRED));
	sChannelCred_.dwVersion = SCHANNEL_CRED_VERSION;
    sChannelCred_.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
	sChannelCred_.dwMaximumCipherStrength = 0;
	sChannelCred_.grbitEnabledProtocols = 0;

	SECURITY_STATUS scRet;
	scRet = AcquireCredentialsHandle(NULL, UNISP_NAME, SECPKG_CRED_OUTBOUND, NULL, &sChannelCred_, NULL, NULL, &hCreds_, NULL);
	if(scRet != SEC_E_OK)
	{
		throw SocketException(this, "Error: AcquireCredentialsHandle() Failed.");
	}

	extraBuffer_ = NULL;
	extraBufferLength_ = 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SslServerSocket::InitiateHandshake()
{
	DWORD dwSSPIFlags;
    DWORD dwSSPIOutFlags;
    
	dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR |
                  ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

    SecBufferDesc outputBufferDesc;
	SecBuffer outputBuffer;
	outputBufferDesc.ulVersion = SECBUFFER_VERSION;
	outputBufferDesc.cBuffers = 1;
	outputBufferDesc.pBuffers = &outputBuffer;
	outputBuffer.BufferType = SECBUFFER_TOKEN;
	outputBuffer.cbBuffer = 0;
	outputBuffer.pvBuffer = NULL;

	in_addr addrTarget;
	addrTarget.S_un.S_addr = ip_;

	SEC_WCHAR wszTargetName[16];
	MultiByteToWideChar(CP_UTF8, 0, inet_ntoa(addrTarget), -1, reinterpret_cast<LPWSTR>(&wszTargetName), 16);

	SECURITY_STATUS scRet = S_OK;
    scRet = InitializeSecurityContext(&hCreds_,
									  NULL,
									  reinterpret_cast<SEC_WCHAR *>(&wszTargetName),
									  dwSSPIFlags,
									  0,
									  SECURITY_NATIVE_DREP,
									  NULL,
									  0,
									  &hContext_,
									  &outputBufferDesc,
									  &dwSSPIOutFlags,
									  NULL);

	if(scRet != SEC_I_CONTINUE_NEEDED)
	{
		throw SocketDisconnectedException(this, "Error: InitializeSecurityContext() Failed.", scRet);
	}

	Send(reinterpret_cast<unsigned char *>(outputBufferDesc.pBuffers[0].pvBuffer), outputBufferDesc.pBuffers[0].cbBuffer);
	FreeContextBuffer(outputBufferDesc.pBuffers[0].pvBuffer);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SslServerSocket::ContinueHandshake(unsigned char *buffer, unsigned int length)
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
		
		scRet = InitializeSecurityContext(&hCreds_,
										  &hContext_,
										  NULL,
										  dwSSPIFlags,
										  0,
										  SECURITY_NATIVE_DREP,
										  &inputBufferDesc,
										  0,
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

		if(scRet == SEC_I_INCOMPLETE_CREDENTIALS)
		{
			extraBufferLength_ = recvBufferLength;
			extraBuffer_ = new char[extraBufferLength_];
			RtlCopyMemory(extraBuffer_, recvBuffer, recvBufferLength);

			GetNewClientCredentials();
			scRet = SEC_I_CONTINUE_NEEDED;
			continue;
		}
		else if(scRet == SEC_E_INCOMPLETE_MESSAGE)
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
				throw SocketDisconnectedException(this, "Error: InitializeSecurityContext() Failed.", scRet);
			}
		}

		break;
	}

	delete [] recvBuffer;
	recvBuffer = NULL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SslServerSocket::GetNewClientCredentials()
{
	HCERTSTORE hCertStore;
	if((hCertStore = CertOpenSystemStore(0, L"MY")) == NULL)
	{
		throw SocketException(this, "Error: CertOpenSystemStore(\"MY\") Failed.");
	}

	SecPkgContext_IssuerListInfoEx issuerListInfo;
	SECURITY_STATUS securityStatus = QueryContextAttributes(&hContext_,
															SECPKG_ATTR_ISSUER_LIST_EX,
															reinterpret_cast<PVOID>(&issuerListInfo));
	if(securityStatus != SEC_E_OK)
	{
		throw SocketException(this, "Error: QueryContextAttributes(SECPKG_ATTR_ISSUER_LIST_EX) Failed.");
	}

	CERT_CHAIN_FIND_BY_ISSUER_PARA findByIssuerPara;
	SecureZeroMemory(&findByIssuerPara, sizeof(CERT_CHAIN_FIND_BY_ISSUER_PARA));
	findByIssuerPara.cbSize = sizeof(CERT_CHAIN_FIND_BY_ISSUER_PARA);
	findByIssuerPara.pszUsageIdentifier = szOID_PKIX_KP_CLIENT_AUTH;
	findByIssuerPara.dwKeySpec = 0;
	findByIssuerPara.cIssuer = issuerListInfo.cIssuers;
	findByIssuerPara.rgIssuer = issuerListInfo.aIssuers;

	while(true)
	{
		PCCERT_CHAIN_CONTEXT pChainContext = NULL;
		pChainContext = CertFindChainInStore(hCertStore,
											 X509_ASN_ENCODING,
											 0,
											 CERT_CHAIN_FIND_BY_ISSUER,
											 &findByIssuerPara,
											 pChainContext);
		if(pChainContext == NULL)
		{
			throw SocketException(this, "Error: CertFindChainInStore() Failed.");
		}

		PCCERT_CONTEXT pCertContext = pChainContext->rgpChain[0]->rgpElement[0]->pCertContext;
		sChannelCred_.dwVersion = SCHANNEL_CRED_VERSION;
		sChannelCred_.cCreds = 1;
		sChannelCred_.paCred = &pCertContext;

		CredHandle hCreds;
		if(AcquireCredentialsHandle(NULL, UNISP_NAME, SECPKG_CRED_OUTBOUND, NULL, &sChannelCred_, NULL, NULL, &hCreds, NULL) != SEC_E_OK)
		{
			continue;
		}

		FreeCredentialsHandle(&hCreds_);
		hCreds_ = hCreds;
		break;
	}

	if(hCertStore != NULL)
    {
        CertCloseStore(hCertStore, 0);
		hCertStore = NULL;
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SslServerSocket::Send(unsigned char *buffer, unsigned int length)
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
		throw SocketDisconnectedException(this, "Error: SslServerSocket::Send() - Buffer Too Large.", -1);
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

void SslServerSocket::SendProtocol(unsigned char *buffer, unsigned int length)
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

Socket *SslServerSocket::OnAccept(SOCKET hSocket)
{
	throw SocketException(this, "Error: SslServerSocket::OnAccept() Not Supported.");
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SslServerSocket::OnConnect()
{
	InitiateHandshake();
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SslServerSocket::OnDisconnect()
{
	if(sslClientSocket_ != NULL)
	{
		sslClientSocket_->Disconnect();
		sslClientSocket_->Release();
		sslClientSocket_ = NULL;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SslServerSocket::OnHandshakeComplete()
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

void SslServerSocket::OnReceive(unsigned char *buffer, unsigned int length, unsigned int ip, unsigned short port)
{
	if(!bSslHandshakeComplete_)
	{
		if(length > 0)
		{
			ContinueHandshake(buffer, length);
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
					if(sslClientSocket_ != NULL)
					{
						unsigned char *modifiedBuffer = NULL;
						unsigned int modifiedBufferLength = 0;

						PyInstance::GetInstance()->ServerRecv(reinterpret_cast<const unsigned char *>(secBuffer[i].pvBuffer),
															  secBuffer[i].cbBuffer,
															  &modifiedBuffer,
															  &modifiedBufferLength);
						if(modifiedBuffer != NULL)
						{
							sslClientSocket_->SendProtocol(modifiedBuffer, modifiedBufferLength);
							delete [] modifiedBuffer;
						}
						else
						{
							sslClientSocket_->SendProtocol(reinterpret_cast<unsigned char *>(secBuffer[i].pvBuffer),
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

void SslServerSocket::OnSendCompletion(DWORD dwNumberOfBytes)
{
	
}

////////////////////////////////////////////////////////////////////////////////////////////////////
