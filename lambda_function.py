#!/usr/bin/python
import json
import socket

def port_scan(host, proto, port):
   s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
   socket.setdefaulttimeout(1)
   result = False
   result = s.connect_ex((host,port))
   if result == 0:
      return True
   else :
      return False

def lambda_handler(event, context):
    
    host = event['host']
    proto = event['proto']
    port = event['port']
    
    result = port_scan(host, proto, port)
    
    return {
        'statusCode': 200,
        'body': result
    }
