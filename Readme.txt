================================================================================
IpPyProxy 0.1.2
Copyright ©2008 Liam Kirton <liam@int3.ws>

15th March 2008
http://int3.ws/
================================================================================

Overview:
---------

IpPyProxy redirects traffic received on a local listening port to a specified
target ip:port, filtering any received data through a dynamically loaded Python
script. IpPyProxy supports both TCP and UDP, although UDP transfers may behave
strangely if multiple applications attempt to communicate with the proxy
simultaneously. This is because each response received from the target will be
delivered to the sender of the last received request - hence the potential for
conflict!

Usage:
------

Listen on TCP localhost:80 and proxy connections to 192.168.0.1:80:
> IpPyProxy.exe -l 80 -t 192.168.0.1:80 -f Scripts\IpPyProxy.py

Listen on UDP localhost:53 and proxy connections to 192.168.0.1:53:
> IpPyProxy.exe -l 53 -t 192.168.0.1:53 -f Scripts\IpPyProxy.py -u

================================================================================