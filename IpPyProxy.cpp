////////////////////////////////////////////////////////////////////////////////////////////////////
// IpPyProxy
//
// Copyright ©2008 Liam Kirton <liam@int3.ws>
////////////////////////////////////////////////////////////////////////////////////////////////////
// IpPyProxy.cpp
//
// Created: 27/02/2008
////////////////////////////////////////////////////////////////////////////////////////////////////

#ifdef _DEBUG
#include <crtdbg.h>
#endif

#include "IpPyProxy.h"

#include <algorithm>
#include <exception>
#include <iostream>
#include <string>
#include <vector>

#include "Mutex.h"
#include "PyInstance.h"
#include "TcpClientSocket.h"
#include "TcpServerSocket.h"
#include "UdpClientSocket.h"
#include "UdpServerSocket.h"

////////////////////////////////////////////////////////////////////////////////////////////////////

static const char *c_IpPyProxyVersion = "0.1.2";

////////////////////////////////////////////////////////////////////////////////////////////////////

BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType);

DWORD WINAPI ProxyThreadProc(LPVOID lpParameter);
DWORD WINAPI WorkerThreadProc(LPVOID lpParameter);

void GetRandomBytes(unsigned char *lpBuffer, DWORD dwCount);
void PrintUsage();

////////////////////////////////////////////////////////////////////////////////////////////////////

CRITICAL_SECTION g_ConsoleCriticalSection;

HANDLE g_hCompletionPort = NULL;
HANDLE g_hExitEvent = NULL;
HANDLE g_hWorkerThreads[2];
HCRYPTPROV g_hCryptProv = NULL;

Mutex g_SocketsMutex;
std::vector<Socket *> g_Sockets;

DWORD g_dwSocketInstanceCount = 0;

USHORT g_LocalPort = 0;
ULONG g_TargetIp = 0;
USHORT g_TargetPort = 0;

std::string g_PyFilterFile = "";

////////////////////////////////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[])
{
#ifdef _DEBUG
	_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
	_CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDOUT);
	_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
	_CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDOUT);
	_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
	_CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDOUT);
	_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG | _CRTDBG_ALLOC_MEM_DF | _CRTDBG_CHECK_ALWAYS_DF);
#endif

	std::cout << std::endl
			  << "IpPyProxy " << c_IpPyProxyVersion << std::endl
			  << "Copyright \xB8" << "2008 Liam Kirton <liam@int3.ws>" << std::endl
			  << std::endl
			  << "Built at " << __TIME__ << " on " << __DATE__ << std::endl << std::endl;

	WSADATA wsaData;
	if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		std::cout << "Fatal Error: WSAStartup() Failed." << std::endl;
		return -1;
	}

	InitializeCriticalSection(&g_ConsoleCriticalSection);
	
	g_PyFilterFile = "IpPyProxy.py";

	Socket *clientSocket = NULL;
	Socket *serverSocket = NULL;

	bool udpOperation = false;

	try
	{
		for(int i = 1; i < argc; ++i)
		{
			std::string cmd = argv[i];
			std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);

			if((cmd == "-l") && ((i + 1) < argc))
			{
				g_LocalPort = static_cast<USHORT>(strtol(argv[++i], NULL, 10));
			}
			else if((cmd == "-t") && ((i + 1) < argc))
			{
				std::string target = argv[++i];
				size_t ipPortDelim = target.find(":");
				if((ipPortDelim == std::string::npos) || (ipPortDelim == 0) || (ipPortDelim >= (target.length() - 1)))
				{
					PrintUsage();
					throw std::exception("Invalid command line parameter.");
				}

				g_TargetIp = ntohl(inet_addr(target.substr(0, ipPortDelim).c_str()));
				g_TargetPort = static_cast<USHORT>(strtol(target.substr(ipPortDelim + 1).c_str(), NULL, 10));
			}
			else if((cmd == "-f") && ((i + 1) < argc))
			{
				g_PyFilterFile = argv[++i];
			}
			else if(cmd == "-u")
			{
				udpOperation = true;
			}
			else
			{
				PrintUsage();
				throw std::exception("Invalid command line parameter.");
			}
		}

		if((g_LocalPort == 0) || (g_TargetIp == 0) || (g_TargetPort == 0))
		{
			PrintUsage();
			throw std::exception("Unspecified command line parameter.");
		}

		std::cout << "Proxying localhost:" << g_LocalPort << " ==> "
				  << ((g_TargetIp & 0xFF000000) >> 24) << "."
				  << ((g_TargetIp & 0x00FF0000) >> 16) << "."
				  << ((g_TargetIp & 0x0000FF00) >> 8) << "."
				  << (g_TargetIp & 0x000000FF) << ":"
				  << g_TargetPort << std::endl << std::endl;

		PyInstance::GetInstance()->Load(g_PyFilterFile);

		if((g_hExitEvent = CreateEvent(NULL, TRUE, FALSE, NULL)) == NULL)
		{
			throw std::exception("CreateEvent() Failed.");
		}

		if(!CryptAcquireContext(&g_hCryptProv, NULL, NULL, PROV_RSA_FULL, 0))
		{
			if(!CryptAcquireContext(&g_hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			{
				throw std::exception("CryptAcquireContext() Failed.");
			}
		}

		SecureZeroMemory(&g_hWorkerThreads, sizeof(g_hWorkerThreads));

		if((g_hCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, NULL, 0)) == NULL)
		{
			throw std::exception("CreateIoCompletionPort(INVALID_HANDLE_VALUE) Failed.");
		}

		for(unsigned int i = 0; i < (sizeof(g_hWorkerThreads) / sizeof(HANDLE)); ++i)
		{
			if((g_hWorkerThreads[i] = CreateThread(NULL, 0, WorkerThreadProc, NULL, 0, NULL)) == NULL)
			{
				throw std::exception("CreateThread() Failed.");
			}
		}

		if(!udpOperation)
		{
			clientSocket = new TcpClientSocket();
			clientSocket->Bind(g_LocalPort);
			clientSocket->Listen();
		}
		else
		{
			clientSocket = new UdpClientSocket();
			serverSocket = new UdpServerSocket(dynamic_cast<UdpClientSocket *>(clientSocket), g_TargetIp, g_TargetPort);

			clientSocket->Bind(g_LocalPort);
			clientSocket->Receive();
			dynamic_cast<UdpClientSocket *>(clientSocket)->SetUdpServerSocket(dynamic_cast<UdpServerSocket *>(serverSocket));

			serverSocket->Bind(0);
			serverSocket->Receive();
		}

		g_SocketsMutex.Lock();
		g_Sockets.push_back(clientSocket);
		g_SocketsMutex.Unlock();

		SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

		EnterCriticalSection(&g_ConsoleCriticalSection);
		std::cout << "Running. Press Ctrl+Break for Prompt, Ctrl+C to Quit." << std::endl << std::endl;
		LeaveCriticalSection(&g_ConsoleCriticalSection);

		if(g_hExitEvent != NULL)
		{
			if(WaitForSingleObject(g_hExitEvent, INFINITE) != WAIT_OBJECT_0)
			{
				EnterCriticalSection(&g_ConsoleCriticalSection);
				std::cout << std::endl << "Warning: WaitForSingleObject() Failed." << std::endl << std::endl;
				LeaveCriticalSection(&g_ConsoleCriticalSection);
			}
		}
	}
	catch(const std::exception &e)
	{
		EnterCriticalSection(&g_ConsoleCriticalSection);
		std::cout << std::endl
				  << "Caught Exception: " << e.what() << std::endl
				  << std::endl;
		LeaveCriticalSection(&g_ConsoleCriticalSection);
	}

	try
	{
		EnterCriticalSection(&g_ConsoleCriticalSection);
		std::cout << std::endl << "Closing." << std::endl << std::endl;
		LeaveCriticalSection(&g_ConsoleCriticalSection);

		SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);

		if(clientSocket != NULL)
		{
			clientSocket->Disconnect();
		}

		PyInstance::GetInstance()->Unload();

		g_SocketsMutex.Lock();
		for(std::vector<Socket *>::iterator i = g_Sockets.begin(); i != g_Sockets.end(); ++i)
		{
			(*i)->Release();
		}
		g_SocketsMutex.Unlock();

		DWORD dwSleepCount = 0;
		while((g_dwSocketInstanceCount > 0) && (++dwSleepCount < 20))
		{
			Sleep(10);
		}
		
		for(unsigned int i = 0; i < sizeof(g_hWorkerThreads) / sizeof(HANDLE); ++i)
		{
			if(g_hCompletionPort != NULL)
			{
				if(PostQueuedCompletionStatus(g_hCompletionPort, 0, 0xFFFFFFFF, NULL) == 0)
				{
					throw std::exception("PostQueuedCompletionStatus() Failed.");
				}
			}
		}

		for(unsigned int i = 0; i < sizeof(g_hWorkerThreads) / sizeof(HANDLE); ++i)
		{
			if(g_hWorkerThreads[i] != NULL)
			{
				if(WaitForSingleObject(g_hWorkerThreads[i], INFINITE) != WAIT_OBJECT_0)
				{
					throw std::exception("WaitForSingleObject(g_hWorkerThreads[i]) Failed.");
				}
			}
		}

		if(g_hCompletionPort != NULL)
		{
			CloseHandle(g_hCompletionPort);
			g_hCompletionPort = NULL;
		}
		
		if(g_hCryptProv != NULL)
		{
			CryptReleaseContext(g_hCryptProv, 0);
			g_hCryptProv = NULL;
		}

		if(g_hExitEvent != NULL)
		{
			CloseHandle(g_hExitEvent);
			g_hExitEvent = NULL;
		}
	}
	catch(const std::exception &e)
	{
		EnterCriticalSection(&g_ConsoleCriticalSection);
		std::cout << std::endl
				  << "Caught Exception: " << e.what() << std::endl
				  << std::endl;
		LeaveCriticalSection(&g_ConsoleCriticalSection);
	}

	DeleteCriticalSection(&g_ConsoleCriticalSection);

	WSACleanup();

#ifdef _DEBUG
	_CrtDumpMemoryLeaks();
#endif

	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType)
{
	switch(dwCtrlType)
	{
		case CTRL_C_EVENT:
		case CTRL_CLOSE_EVENT:
		case CTRL_LOGOFF_EVENT:
		case CTRL_SHUTDOWN_EVENT:
			SetEvent(g_hExitEvent);
			break;

		case CTRL_BREAK_EVENT:
			static bool writtenHelp = false;
			std::string command;
			
			EnterCriticalSection(&g_ConsoleCriticalSection);
			if(!writtenHelp)
			{
				std::cout << std::endl << "Hint: Type 'r' to reload .py" << std::endl << std::endl;
				writtenHelp = true;
			}

			std::cout << "> " << std::flush;
			std::cin >> command;
			LeaveCriticalSection(&g_ConsoleCriticalSection);

			if(command == "r")
			{
				PyInstance::GetInstance()->Unload();
				PyInstance::GetInstance()->Load(g_PyFilterFile);
			}
			else
			{
				PyInstance::GetInstance()->CommandHandler(reinterpret_cast<const unsigned char *>(command.c_str()));
			}
			break;
	}

	return TRUE;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

DWORD WINAPI WorkerThreadProc(LPVOID lpParameter)
{
	DWORD dwNumberOfBytes;
	ULONG ulCompletionKey;
	LPOVERLAPPED lpOverlapped;

	while(true)
	{	
		GetQueuedCompletionStatus(g_hCompletionPort,
								  &dwNumberOfBytes,
								  &ulCompletionKey,
								  &lpOverlapped,
								  INFINITE);

		if((ulCompletionKey == NULL) || (ulCompletionKey == 0xFFFFFFFF))
		{
			break;
		}

		g_SocketsMutex.Lock();
		Socket *completionSocket = reinterpret_cast<Socket *>(ulCompletionKey);
		completionSocket->AddRef();
		g_SocketsMutex.Unlock();

		try
		{
			completionSocket->OnCompletion(dwNumberOfBytes, lpOverlapped);
		}
		catch(const SocketDisconnectedException &e)
		{
			g_SocketsMutex.Lock();
			for(std::vector<Socket *>::iterator i = g_Sockets.begin(); i != g_Sockets.end(); ++i)
			{
				if((*i) == e.socket_)
				{
					EnterCriticalSection(&g_ConsoleCriticalSection);
					std::cout << "Disconnected. ";
					if(e.error_ != 0)
					{
						std::cout << e.what() << " [0x" << std::hex << e.error_ << std::dec << "]";
					}
					std::cout << std::endl;
					LeaveCriticalSection(&g_ConsoleCriticalSection);

					e.socket_->Disconnect();
					e.socket_->OnDisconnect();
					e.socket_->Release();
					g_Sockets.erase(i);
					break;
				}				
			}
			g_SocketsMutex.Unlock();
		}
		catch(const std::exception &e)
		{
			EnterCriticalSection(&g_ConsoleCriticalSection);
			std::cout << std::endl
					  << "--------------------------------------------------------------------------------" << std::endl
					  << "WorkerThreadProc[" << GetCurrentThreadId() << "] Caught Fatal Exception: " << e.what() << std::endl
					  << "GetLastError(): " << GetLastError() << std::endl
					  << "WSAGetLastError(): " << WSAGetLastError() << std::endl
					  << "--------------------------------------------------------------------------------" << std::endl
					  << std::endl;
			LeaveCriticalSection(&g_ConsoleCriticalSection);

			SetEvent(g_hExitEvent);
		}

		g_SocketsMutex.Lock();
		completionSocket->Release();
		g_SocketsMutex.Unlock();
	}

	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void GetRandomBytes(unsigned char *lpBuffer, DWORD dwCount)
{
	if(!CryptGenRandom(g_hCryptProv, dwCount, reinterpret_cast<BYTE *>(lpBuffer)))
	{
		throw std::exception("CryptGenRandom() Failed.");
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void PrintUsage()
{
	std::cout << "Usage: IpPyProxy.exe -l <p> -t <a.b.c.d:p> -f <filter.py> -u" << std::endl << std::endl;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
