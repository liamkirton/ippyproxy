// ========================================================================================================================
// IpPyProxy
//
// Copyright ©2008 Liam Kirton <liam@int3.ws>
// ========================================================================================================================
// PyInstance.cpp
//
// Created: 29/02/2008
// ========================================================================================================================

#include "PyInstance.h"

#include <iostream>

#include "IpPyProxy.h"

// ========================================================================================================================

static PyInstance g_PyInstance;

// ========================================================================================================================

static PyMethodDef IpPyProxyMethods[] =
{
	{"set_command_handler", PyInstance::SetCommandHandler, METH_VARARGS, NULL},
    {"set_tcp_client_recv_filter", PyInstance::SetTcpClientRecvFilter, METH_VARARGS, NULL},
	{"set_tcp_server_recv_filter", PyInstance::SetTcpServerRecvFilter, METH_VARARGS, NULL},
	{"set_udp_client_recv_filter", PyInstance::SetUdpClientRecvFilter, METH_VARARGS, NULL},
	{"set_udp_server_recv_filter", PyInstance::SetUdpServerRecvFilter, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

// ========================================================================================================================

PyInstance::PyInstance() : pyCommandHandler_(NULL),
						   pyTcpClientRecvFilter_(NULL),
						   pyTcpServerRecvFilter_(NULL),
						   pyUdpClientRecvFilter_(NULL),
						   pyUdpServerRecvFilter_(NULL)
{
	
}

// ========================================================================================================================

PyInstance::~PyInstance()
{
	Unload();
}

// ========================================================================================================================

void PyInstance::Load(const std::string &path)
{
	std::cout << "Loading \"" << path << "\"." << std::endl;

	__try
	{
		mutex_.Lock();
	
		Py_Initialize();
		Py_InitModule("ippyproxy", IpPyProxyMethods);
	
		HANDLE hPyFilter = INVALID_HANDLE_VALUE;
		if((hPyFilter = CreateFileA(path.c_str(),
								    GENERIC_READ,
								    FILE_SHARE_READ,
								    NULL,
								    OPEN_EXISTING,
								    FILE_ATTRIBUTE_NORMAL,
								    NULL)) != INVALID_HANDLE_VALUE)
		{
			HANDLE hPyFilterMapping = NULL;
			if((hPyFilterMapping = CreateFileMapping(hPyFilter, NULL, PAGE_READONLY, 0, GetFileSize(hPyFilter, NULL), NULL)) != NULL)
			{
				char *pPyFilter = reinterpret_cast<char *>(MapViewOfFile(hPyFilterMapping, FILE_MAP_READ, 0, 0, 0));
				if(pPyFilter != NULL)
				{
					char *pPyBuffer = new char[GetFileSize(hPyFilter, NULL) + 1];
					RtlCopyMemory(pPyBuffer, pPyFilter, GetFileSize(hPyFilter, NULL));
					pPyBuffer[GetFileSize(hPyFilter, NULL)] = '\0';
					PyRun_SimpleString(pPyBuffer);
					delete [] pPyBuffer;
					
					if((pyCommandHandler_ == NULL) || (pyTcpClientRecvFilter_ == NULL) || (pyTcpServerRecvFilter_ == NULL))
					{
						std::cout << "Warning: Python IpPyProxy.set_command_handler Or IpPyProxy.set_client_recv_filter Or IpPyProxy.set_server_recv_filter Not Called." << std::endl;
					}
	
					UnmapViewOfFile(pPyFilter);
				}
				else
				{
					std::cout << "Warning: MapViewOfFile() Failed." << std::endl;
					return;
				}
				CloseHandle(hPyFilterMapping);
			}
			else
			{
				std::cout << "Warning: CreateFileMapping() Failed." << std::endl;
			}
	
			CloseHandle(hPyFilter);
		}
		else
		{
			std::cout << "Warning: CreateFile(\"" << path << "\") Failed." << std::endl;
		}
	
		std::cout << std::endl;
	}
	__finally
	{
		mutex_.Unlock();
	}
}

// ========================================================================================================================

void PyInstance::Unload()
{
	if(pyTcpClientRecvFilter_ != NULL)
	{
		Py_DECREF(pyTcpClientRecvFilter_);
		pyTcpClientRecvFilter_ = NULL;
	}
	if(pyTcpServerRecvFilter_ != NULL)
	{
		Py_DECREF(pyTcpServerRecvFilter_);
		pyTcpServerRecvFilter_ = NULL;
	}

	Py_Finalize();
}

// ========================================================================================================================

PyInstance *PyInstance::GetInstance()
{
	return &g_PyInstance;
}

// ========================================================================================================================

void PyInstance::CommandHandler(const unsigned char *command)
{
	__try
	{
		mutex_.Lock();

		if(pyTcpClientRecvFilter_ == NULL)
		{
			std::cout << "Warning: PyInstance::TcpClientRecv() Called With pyTcpClientRecvFilter_ NULL." << std::endl;
		}
		else
		{
			PyObject *arglist = Py_BuildValue("(s#)", command, strlen(reinterpret_cast<const char *>(command)));
			PyObject *result = PyEval_CallObject(pyCommandHandler_, arglist);
			Py_DECREF(arglist);
			arglist = NULL;

			if(result != NULL)
			{
				Py_DECREF(result);
			}
			else
			{
				PyErr_WriteUnraisable(pyCommandHandler_);
			}
		}
	}
	__finally
	{
		mutex_.Unlock();
	}
}

// ========================================================================================================================

void PyInstance::TcpClientRecv(const unsigned char *buffer,
							   const unsigned int bufferLength,
							   unsigned char **modifiedBuffer,
							   unsigned int *modifiedBufferLength)
{
	__try
	{
		mutex_.Lock();

		if(pyTcpClientRecvFilter_ == NULL)
		{
			std::cout << "Warning: PyInstance::TcpClientRecv() Called With pyTcpClientRecvFilter_ NULL." << std::endl;
		}
		else
		{
			PyObject *arglist = Py_BuildValue("(s#)", buffer, bufferLength);
			PyObject *result = PyEval_CallObject(pyTcpClientRecvFilter_, arglist);
			Py_DECREF(arglist);
			arglist = NULL;

			if(result != NULL)
			{
				if(result != Py_None)
				{
					PyObject *pReturnBuffer = NULL;
					unsigned int pReturnBufferLen = 0;
					char fillChar = '\0';

					if(PyArg_Parse(result, "s#", &pReturnBuffer, &pReturnBufferLen))
					{
						*modifiedBuffer = new unsigned char[pReturnBufferLen];
						*modifiedBufferLength = pReturnBufferLen;

						RtlCopyMemory(*modifiedBuffer, reinterpret_cast<unsigned char *>(pReturnBuffer), pReturnBufferLen);
					}
					else
					{
						*modifiedBuffer = NULL;
						*modifiedBufferLength = 0;
						PyErr_WriteUnraisable(pyTcpClientRecvFilter_);
					}
					PyErr_Clear();
				}

				Py_DECREF(result);
			}
			else
			{
				*modifiedBuffer = NULL;
				*modifiedBufferLength = 0;
				PyErr_WriteUnraisable(pyTcpClientRecvFilter_);
			}
		}
	}
	__finally
	{
		mutex_.Unlock();
	}
}

// ========================================================================================================================

void PyInstance::TcpServerRecv(const unsigned char *buffer,
							   const unsigned int bufferLength,
							   unsigned char **modifiedBuffer,
							   unsigned int *modifiedBufferLength)
{
	__try
	{
		mutex_.Lock();

		if(pyTcpServerRecvFilter_ == NULL)
		{
			std::cout << "Warning: PyInstance::TcpClientRecv() Called With pyTcpServerRecvFilter_ NULL." << std::endl;
		}
		else
		{
			PyObject *arglist = Py_BuildValue("(s#)", buffer, bufferLength);
			PyObject *result = PyEval_CallObject(pyTcpServerRecvFilter_, arglist);
			Py_DECREF(arglist);
			arglist = NULL;

			if(result != NULL)
			{
				if(result != Py_None)
				{
					PyObject *pReturnBuffer = NULL;
					unsigned int pReturnBufferLen = 0;
					char fillChar = '\0';

					if(PyArg_Parse(result, "s#", &pReturnBuffer, &pReturnBufferLen))
					{
						*modifiedBuffer = new unsigned char[pReturnBufferLen];
						*modifiedBufferLength = pReturnBufferLen;

						RtlCopyMemory(*modifiedBuffer, reinterpret_cast<unsigned char *>(pReturnBuffer), pReturnBufferLen);
					}
					else
					{
						*modifiedBuffer = NULL;
						*modifiedBufferLength = 0;
						PyErr_WriteUnraisable(pyTcpServerRecvFilter_);
					}
					PyErr_Clear();
				}

				Py_DECREF(result);
			}
			else
			{
				*modifiedBuffer = NULL;
				*modifiedBufferLength = 0;
				PyErr_WriteUnraisable(pyTcpServerRecvFilter_);
			}
		}
	}
	__finally
	{
		mutex_.Unlock();
	}
}

// ========================================================================================================================

void PyInstance::UdpClientRecv(const unsigned char *buffer,
							   const unsigned int bufferLength,
							   unsigned char **modifiedBuffer,
							   unsigned int *modifiedBufferLength)
{
	__try
	{
		mutex_.Lock();

		if(pyUdpClientRecvFilter_ == NULL)
		{
			std::cout << "Warning: PyInstance::UdpClientRecv() Called With pyUdpClientRecvFilter_ NULL." << std::endl;
		}
		else
		{
			PyObject *arglist = Py_BuildValue("(s#)", buffer, bufferLength);
			PyObject *result = PyEval_CallObject(pyUdpClientRecvFilter_, arglist);
			Py_DECREF(arglist);
			arglist = NULL;

			if(result != NULL)
			{
				if(result != Py_None)
				{
					PyObject *pReturnBuffer = NULL;
					unsigned int pReturnBufferLen = 0;
					char fillChar = '\0';

					if(PyArg_Parse(result, "s#", &pReturnBuffer, &pReturnBufferLen))
					{
						*modifiedBuffer = new unsigned char[pReturnBufferLen];
						*modifiedBufferLength = pReturnBufferLen;

						RtlCopyMemory(*modifiedBuffer, reinterpret_cast<unsigned char *>(pReturnBuffer), pReturnBufferLen);
					}
					else
					{
						*modifiedBuffer = NULL;
						*modifiedBufferLength = 0;
						PyErr_WriteUnraisable(pyUdpClientRecvFilter_);
					}
					PyErr_Clear();
				}

				Py_DECREF(result);
			}
			else
			{
				*modifiedBuffer = NULL;
				*modifiedBufferLength = 0;
				PyErr_WriteUnraisable(pyUdpClientRecvFilter_);
			}
		}
	}
	__finally
	{
		mutex_.Unlock();
	}
}

// ========================================================================================================================

void PyInstance::UdpServerRecv(const unsigned char *buffer,
							   const unsigned int bufferLength,
							   unsigned char **modifiedBuffer,
							   unsigned int *modifiedBufferLength)
{
	__try
	{
		mutex_.Lock();

		if(pyUdpServerRecvFilter_ == NULL)
		{
			std::cout << "Warning: PyInstance::UdpClientRecv() Called With pyUdpServerRecvFilter_ NULL." << std::endl;
		}
		else
		{
			PyObject *arglist = Py_BuildValue("(s#)", buffer, bufferLength);
			PyObject *result = PyEval_CallObject(pyUdpServerRecvFilter_, arglist);
			Py_DECREF(arglist);
			arglist = NULL;

			if(result != NULL)
			{
				if(result != Py_None)
				{
					PyObject *pReturnBuffer = NULL;
					unsigned int pReturnBufferLen = 0;
					char fillChar = '\0';

					if(PyArg_Parse(result, "s#", &pReturnBuffer, &pReturnBufferLen))
					{
						*modifiedBuffer = new unsigned char[pReturnBufferLen];
						*modifiedBufferLength = pReturnBufferLen;

						RtlCopyMemory(*modifiedBuffer, reinterpret_cast<unsigned char *>(pReturnBuffer), pReturnBufferLen);
					}
					else
					{
						*modifiedBuffer = NULL;
						*modifiedBufferLength = 0;
						PyErr_WriteUnraisable(pyUdpServerRecvFilter_);
					}
					PyErr_Clear();
				}

				Py_DECREF(result);
			}
			else
			{
				*modifiedBuffer = NULL;
				*modifiedBufferLength = 0;
				PyErr_WriteUnraisable(pyUdpServerRecvFilter_);
			}
		}
	}
	__finally
	{
		mutex_.Unlock();
	}
}

// ========================================================================================================================

PyObject *PyInstance::SetCommandHandler(PyObject *dummy, PyObject *args)
{
	PyObject *pyResult = NULL;

	__try
	{
		g_PyInstance.mutex_.Lock();

		if(PyArg_ParseTuple(args, "O", &g_PyInstance.pyCommandHandler_))
		{
			if(!PyCallable_Check(g_PyInstance.pyCommandHandler_))
			{
				PyErr_SetString(PyExc_TypeError, "Error: SetCommandHandler() - Parameter Must Be Callable.");
			}
			else
			{
				Py_XINCREF(g_PyInstance.pyCommandHandler_); 
				Py_INCREF(Py_None);
				pyResult = Py_None;
			}
		}
	}
	__finally
	{
		g_PyInstance.mutex_.Unlock();
	}
    return pyResult;
}

// ========================================================================================================================

PyObject *PyInstance::SetTcpClientRecvFilter(PyObject *dummy, PyObject *args)
{
	PyObject *pyResult = NULL;

	__try
	{
		g_PyInstance.mutex_.Lock();

		if(PyArg_ParseTuple(args, "O", &g_PyInstance.pyTcpClientRecvFilter_))
		{
			if(!PyCallable_Check(g_PyInstance.pyTcpClientRecvFilter_))
			{
				PyErr_SetString(PyExc_TypeError, "Error: SetTcpClientRecvFilter() - Parameter Must Be Callable.");
			}
			else
			{
				Py_XINCREF(g_PyInstance.pyTcpClientRecvFilter_); 
				Py_INCREF(Py_None);
				pyResult = Py_None;
			}
		}
	}
	__finally
	{
		g_PyInstance.mutex_.Unlock();
	}
    return pyResult;
}

// ========================================================================================================================

PyObject *PyInstance::SetTcpServerRecvFilter(PyObject *dummy, PyObject *args)
{
	PyObject *pyResult = NULL;

	__try
	{
		g_PyInstance.mutex_.Lock();

		if(PyArg_ParseTuple(args, "O", &g_PyInstance.pyTcpServerRecvFilter_))
		{
			if(!PyCallable_Check(g_PyInstance.pyTcpServerRecvFilter_))
			{
				PyErr_SetString(PyExc_TypeError, "Error: SetTcpServerRecvFilter() - Parameter Must Be Callable.");
			}
			else
			{
				Py_XINCREF(g_PyInstance.pyTcpServerRecvFilter_); 
				Py_INCREF(Py_None);
				pyResult = Py_None;
			}
		}
	}
	__finally
	{
		g_PyInstance.mutex_.Unlock();
	}
    return pyResult;
}

// ========================================================================================================================

PyObject *PyInstance::SetUdpClientRecvFilter(PyObject *dummy, PyObject *args)
{
	PyObject *pyResult = NULL;

	__try
	{
		g_PyInstance.mutex_.Lock();

		if(PyArg_ParseTuple(args, "O", &g_PyInstance.pyUdpClientRecvFilter_))
		{
			if(!PyCallable_Check(g_PyInstance.pyUdpClientRecvFilter_))
			{
				PyErr_SetString(PyExc_TypeError, "Error: SetUdpClientRecvFilter() - Parameter Must Be Callable.");
			}
			else
			{
				Py_XINCREF(g_PyInstance.pyUdpClientRecvFilter_); 
				Py_INCREF(Py_None);
				pyResult = Py_None;
			}
		}
	}
	__finally
	{
		g_PyInstance.mutex_.Unlock();
	}
    return pyResult;
}

// ========================================================================================================================

PyObject *PyInstance::SetUdpServerRecvFilter(PyObject *dummy, PyObject *args)
{
	PyObject *pyResult = NULL;

	__try
	{
		g_PyInstance.mutex_.Lock();

		if(PyArg_ParseTuple(args, "O", &g_PyInstance.pyUdpServerRecvFilter_))
		{
			if(!PyCallable_Check(g_PyInstance.pyUdpServerRecvFilter_))
			{
				PyErr_SetString(PyExc_TypeError, "Error: SetUdpServerRecvFilter() - Parameter Must Be Callable.");
			}
			else
			{
				Py_XINCREF(g_PyInstance.pyUdpServerRecvFilter_); 
				Py_INCREF(Py_None);
				pyResult = Py_None;
			}
		}
	}
	__finally
	{
		g_PyInstance.mutex_.Unlock();
	}
    return pyResult;
}

// ========================================================================================================================
