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
	
def tcp_client_recv_filter(buffer):
	print "tcp_client_recv_filter(%d)" % len(buffer)
	return buffer

# --------------------------------------------------------------------------------

def tcp_server_recv_filter(buffer):
	print "tcp_server_recv_filter(%d)" % len(buffer)
	return buffer

# --------------------------------------------------------------------------------

def udp_client_recv_filter(buffer):
	print "udp_client_recv_filter(%d)" % len(buffer)
	return buffer

# --------------------------------------------------------------------------------

def udp_server_recv_filter(buffer):
	print "udp_server_recv_filter(%d)" % len(buffer)
	return buffer
	
# --------------------------------------------------------------------------------

if __name__ == '__main__':
	ippyproxy.set_command_handler(command_handler)
	ippyproxy.set_tcp_client_recv_filter(tcp_client_recv_filter)
	ippyproxy.set_tcp_server_recv_filter(tcp_server_recv_filter)
	ippyproxy.set_udp_client_recv_filter(udp_client_recv_filter)
	ippyproxy.set_udp_server_recv_filter(udp_server_recv_filter)
	print '\"IpPyProxy.py\" Loaded.'

# --------------------------------------------------------------------------------
