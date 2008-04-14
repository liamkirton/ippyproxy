// ========================================================================================================================
// IpPyProxy
//
// Copyright ©2008 Liam Kirton <liam@int3.ws>
// ========================================================================================================================
// PyInstance.h
//
// Created: 29/02/2008
// ========================================================================================================================

#pragma once

// ========================================================================================================================

#include "Includes.h"

#ifdef _DEBUG
#undef _DEBUG
#include <python.h>
#define _DEBUG
#else
#include <python.h>
#endif

#include <string>

#include "Mutex.h"

// ========================================================================================================================

class PyInstance
{
public:
	PyInstance();
	~PyInstance();

	void Load(const std::string &path);
	void Unload();
	
	void CommandHandler(const unsigned char *command);

	void TcpClientRecv(const unsigned char *buffer,
					   const unsigned int bufferLength,
					   unsigned char **modifiedBuffer,
					   unsigned int *modifiedBufferLength);

	void TcpServerRecv(const unsigned char *buffer,
					   const unsigned int bufferLength,
					   unsigned char **modifiedBuffer,
					   unsigned int *modifiedBufferLength);

	void UdpClientRecv(const unsigned char *buffer,
					   const unsigned int bufferLength,
					   unsigned char **modifiedBuffer,
					   unsigned int *modifiedBufferLength);

	void UdpServerRecv(const unsigned char *buffer,
					   const unsigned int bufferLength,
					   unsigned char **modifiedBuffer,
					   unsigned int *modifiedBufferLength);

	static PyInstance *GetInstance();
	static PyObject *PyInstance::SetCommandHandler(PyObject *dummy, PyObject *args);
	static PyObject *PyInstance::SetTcpClientRecvFilter(PyObject *dummy, PyObject *args);
	static PyObject *PyInstance::SetTcpServerRecvFilter(PyObject *dummy, PyObject *args);
	static PyObject *PyInstance::SetUdpClientRecvFilter(PyObject *dummy, PyObject *args);
	static PyObject *PyInstance::SetUdpServerRecvFilter(PyObject *dummy, PyObject *args);

private:
	Mutex mutex_;
	
	PyObject *pyCommandHandler_;
	PyObject *pyTcpClientRecvFilter_;
	PyObject *pyTcpServerRecvFilter_;
	PyObject *pyUdpClientRecvFilter_;
	PyObject *pyUdpServerRecvFilter_;
};

// ========================================================================================================================
