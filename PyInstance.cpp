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
    {"set_client_recv_filter", PyInstance::SetClientRecvFilter, METH_VARARGS, NULL},
	{"set_server_recv_filter", PyInstance::SetServerRecvFilter, METH_VARARGS, NULL},
	{NULL, NULL, 0, NULL}
};

// ========================================================================================================================

PyInstance::PyInstance() : pyCommandHandler_(NULL),
						   pyClientRecvFilter_(NULL),
						   pyServerRecvFilter_(NULL)
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
					
					if((pyCommandHandler_ == NULL) ||
					   (pyClientRecvFilter_ == NULL) ||
					   (pyServerRecvFilter_ == NULL))
					{
						std::cout << "Warning: Python Required Callback Not Set." << std::endl;
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
	if(pyClientRecvFilter_ != NULL)
	{
		Py_DECREF(pyClientRecvFilter_);
		pyClientRecvFilter_ = NULL;
	}
	if(pyServerRecvFilter_ != NULL)
	{
		Py_DECREF(pyServerRecvFilter_);
		pyServerRecvFilter_ = NULL;
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

		if(pyCommandHandler_ == NULL)
		{
			std::cout << "Warning: PyInstance::CommandHandler() Called With pyCommandHandler_ NULL." << std::endl;
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

void PyInstance::ClientRecv(const unsigned char *buffer,
							const unsigned int bufferLength,
							unsigned char **modifiedBuffer,
							unsigned int *modifiedBufferLength)
{
	__try
	{
		mutex_.Lock();

		if(pyClientRecvFilter_ == NULL)
		{
			std::cout << "Warning: PyInstance::ClientRecv() Called With pyClientRecvFilter_ NULL." << std::endl;
		}
		else
		{
			PyObject *arglist = Py_BuildValue("(s#)", buffer, bufferLength);
			PyObject *result = PyEval_CallObject(pyClientRecvFilter_, arglist);
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
						PyErr_WriteUnraisable(pyClientRecvFilter_);
					}
					PyErr_Clear();
				}

				Py_DECREF(result);
			}
			else
			{
				*modifiedBuffer = NULL;
				*modifiedBufferLength = 0;
				PyErr_WriteUnraisable(pyClientRecvFilter_);
			}
		}
	}
	__finally
	{
		mutex_.Unlock();
	}
}

// ========================================================================================================================

void PyInstance::ServerRecv(const unsigned char *buffer,
							   const unsigned int bufferLength,
							   unsigned char **modifiedBuffer,
							   unsigned int *modifiedBufferLength)
{
	__try
	{
		mutex_.Lock();

		if(pyServerRecvFilter_ == NULL)
		{
			std::cout << "Warning: PyInstance::ServerRecv() Called With pyServerRecvFilter_ NULL." << std::endl;
		}
		else
		{
			PyObject *arglist = Py_BuildValue("(s#)", buffer, bufferLength);
			PyObject *result = PyEval_CallObject(pyServerRecvFilter_, arglist);
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
						PyErr_WriteUnraisable(pyServerRecvFilter_);
					}
					PyErr_Clear();
				}

				Py_DECREF(result);
			}
			else
			{
				*modifiedBuffer = NULL;
				*modifiedBufferLength = 0;
				PyErr_WriteUnraisable(pyServerRecvFilter_);
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

PyObject *PyInstance::SetClientRecvFilter(PyObject *dummy, PyObject *args)
{
	PyObject *pyResult = NULL;

	__try
	{
		g_PyInstance.mutex_.Lock();

		if(PyArg_ParseTuple(args, "O", &g_PyInstance.pyClientRecvFilter_))
		{
			if(!PyCallable_Check(g_PyInstance.pyClientRecvFilter_))
			{
				PyErr_SetString(PyExc_TypeError, "Error: SetClientRecvFilter() - Parameter Must Be Callable.");
			}
			else
			{
				Py_XINCREF(g_PyInstance.pyClientRecvFilter_); 
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

PyObject *PyInstance::SetServerRecvFilter(PyObject *dummy, PyObject *args)
{
	PyObject *pyResult = NULL;

	__try
	{
		g_PyInstance.mutex_.Lock();

		if(PyArg_ParseTuple(args, "O", &g_PyInstance.pyServerRecvFilter_))
		{
			if(!PyCallable_Check(g_PyInstance.pyServerRecvFilter_))
			{
				PyErr_SetString(PyExc_TypeError, "Error: SetServerRecvFilter() - Parameter Must Be Callable.");
			}
			else
			{
				Py_XINCREF(g_PyInstance.pyServerRecvFilter_); 
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
