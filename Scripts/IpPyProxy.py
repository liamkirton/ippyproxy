# --------------------------------------------------------------------------------
# IpPyProxy
#
# Copyright ©2008 Liam Kirton <liam@int3.ws>
# --------------------------------------------------------------------------------
# IpPyProxy.py
#
# Created: 29/02/2008
# --------------------------------------------------------------------------------

import ippyproxy

# --------------------------------------------------------------------------------

def command_handler(command):
	print "command_handler(%s)" % command

# --------------------------------------------------------------------------------

def client_recv_filter(buffer):
	print "client_recv_filter(%d)" % len(buffer)
	return buffer

# --------------------------------------------------------------------------------

def server_recv_filter(buffer):
	print "server_recv_filter(%d)" % len(buffer)
	return buffer

# --------------------------------------------------------------------------------

if __name__ == '__main__':
	ippyproxy.set_command_handler(command_handler)
	ippyproxy.set_client_recv_filter(client_recv_filter)
	ippyproxy.set_server_recv_filter(server_recv_filter)
	print '\"IpPyProxy.py\" Loaded.'

# --------------------------------------------------------------------------------
