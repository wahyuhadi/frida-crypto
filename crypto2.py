import time
import frida
import json
import pprint
import os
import sys
import argparse


enc_cipher_hashcodes = [] 
dec_cipher_hashcodes = []


def my_message_handler(message, payload):
    if message["type"] == "send":
        my_json = json.loads(message["payload"])
        
        # if my_json["my_type"] == "KEY":
        #     print ("[+] Key sent to SecretKeySpec() :", payload)
        # elif my_json["my_type"] == "IV":
        #     print ("[+] Iv sent to IvParameterSpec()", payload)

        if my_json["my_type"] == "hashcode_enc":
            enc_cipher_hashcodes.append(my_json["hashcode"])
        
        elif my_json["my_type"] == "hashcode_dec":
            dec_cipher_hashcodes.append(my_json["hashcode"])
       
        elif my_json["my_type"] == "Key from call to cipher init":
            print ("\n\n")
            print ("[+] Key sent to cipher init()", payload.hex())
        
        elif my_json["my_type"] == "IV from call to cipher init":
            print ("[+] Iv sent to cipher init()", payload.hex())
        
        elif my_json["my_type"] == "before_doFinal" and my_json["hashcode"] in enc_cipher_hashcodes:
            print ("Data to be encrypted :")
            print (str(payload, 'utf-8'))

        
        elif my_json["my_type"] == "after_doFinal" and my_json["hashcode"] in dec_cipher_hashcodes:
            print ("Decrypted data :")
            pp = pprint.PrettyPrinter(indent=4)
            pp.pprint (json.loads(payload))
        
    else:
        print (message)
        print ('*' * 16)
        print (payload)




if __name__ == '__main__':
    try:
       
        device = frida.get_usb_device()
        pid = device.spawn(['com.xxx.xxx'])
        device.resume(pid)
        time.sleep(1)  # Without it Java.perform silently fails
        session = device.attach(pid)

       
        with open('crypto.js') as f:
            script = session.create_script(f.read())
        script.on("message", my_message_handler)  # register the message handler
        script.load()
        print('')
        sys.stdin.read()

    except KeyboardInterrupt:
        sys.exit(0) 