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

	void ClientRecv(const unsigned char *buffer,
					const unsigned int bufferLength,
					unsigned char **modifiedBuffer,
					unsigned int *modifiedBufferLength);

	void ServerRecv(const unsigned char *buffer,
					const unsigned int bufferLength,
					unsigned char **modifiedBuffer,
					unsigned int *modifiedBufferLength);

	static PyInstance *GetInstance();
	static PyObject *PyInstance::SetCommandHandler(PyObject *dummy, PyObject *args);
	static PyObject *PyInstance::SetClientRecvFilter(PyObject *dummy, PyObject *args);
	static PyObject *PyInstance::SetServerRecvFilter(PyObject *dummy, PyObject *args);

private:
	Mutex mutex_;
	
	PyObject *pyCommandHandler_;
	PyObject *pyClientRecvFilter_;
	PyObject *pyServerRecvFilter_;
};

// ========================================================================================================================
