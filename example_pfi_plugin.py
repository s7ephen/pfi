#!/usr/bin/env python
import sys
readdata = ""
somedataread = False
while 1:
    try:
        readdata += sys.stdin.next()        
        if len(readdata) > 0:
            somedataread = True
    except StopIteration:
        if somedataread == True:
            break
sys.stdout.write("TAMPERED WITH!"+readdata) 
