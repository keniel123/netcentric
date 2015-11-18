# Client to implement simplified RSA algorithm.
# The client says hello to the server, and the server responds with a Hello
# and its public key. The client then sends a session key encrypted with the
# server's public key. The server responds to this message with a nonce
# encrypted with the server's public key. The client decrypts the nonce
# and sends it back to the server encrypted with the session key. Finally,
# the server sends the client a message with a status code.
# Author: fokumdt 2015-10-18

#!/usr/bin/python3

import socket
import math
import random
import simplified_AES


def expMod(b,n,m):
        """Computes the modular exponent of a number returns (b^n mod m)"""
        if n==0:
                return 1
        elif n%2==0:
                return expMod((b*b)%m, n/2, m)
        else:
                return(b*expMod(b,n-1,m))%m

def modular_Exponentiation(a,b,n):
    x=1
    while(b>0):
        if (b&1==1):x=(x*a)%n
        a=(a*a)%n
        b >>= 1# represents binary conversion for example a >> = 15 (means 0000 1111)
    return x%n

def gcd_iter(u, v):
    """Iterative Euclidean algorithm"""
    while v != 0:
        u, v = v, u % v
    return u


def genKeys(p, q):#Client generates its Public and Private Key 
     """Generate n, phi(n), e, and d."""
     # Fill in code to generate the server's public and private keys.
     # Make sure to use the Extended Euclidean algorithm.
     clientN=p*q
     clientPHI=(p-1)*(q-1)
     clientE= random.randrange(1,clientPHI)
     t=gcd_iter(clientE,clientPHI)
     while t!=1:
        clientE=random.randrange(1,clientPHI)
        t=gcd_iter(clientE,clientPHI)
     return clientN,clientE

def RSAencrypt(m, e, n):
    """Encryption side of RSA"""
    # Write code to do RSA encryption
    c=expMod(m,e,n)
    return c

    
def RSAdecrypt(c, d, n):
        """Decryption side of RSA"""
        # Write code to RSA decryption
        m=expMod(c,d,n)
        return m

def serverHello():
        """Sends server hello message"""
        status = "100 Hello"
        return status

def sendSessionKey(s):
        """Sends server session key"""
        status = "112 SessionKey " + str(s)
        return status

def prime(n):
    for i in range(2,n):
        if n%i==0:
            return False
    return True

def isprime(n):
    """
        return true if n is a prime number and false otherwise"""
    if prime(n):
        return True
    else:
        return False

def sendTransformedNonce(xform):
        """Sends server nonce encrypted with session key"""
        status = "130 " + str(xform)
        return status

def computeSessionKey():
        """Computes this node's session key"""
        sessionKey = random.randint(1, 32768)
        return sessionKey
        


def main():
        """Driver function for the project"""
        serverHost = 'localhost'        # The remote host
        serverPort = 9000               # The same port as used by the server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((serverHost, serverPort))
        msg = serverHello()
        s.sendall(bytes(msg,'utf-8'))  # Sending bytes encoded in utf-8 format.
        data = s.recv(1024).decode('utf-8')
        strStatus = "105 Hello"
        if data and data.find(strStatus) < 0:
                print("Invalid data received. Closing")
        else:
                # Write appropriate code to parse received string and extract
                # the modulus and exponent for public key encryption.
                n = int(data.split()[2]) # Modulus for public key encryption
                e = int(data.split()[3])  # Exponent for public key encryption
                print("Server's public key: ("+ str(n)+","+str(e)+")")
                symmetricKey = computeSessionKey()
                print ("Symmetric Key:" + str(symmetricKey)) 
                encSymmKey = RSAencrypt(symmetricKey, e, n)
                print ("Encrypted Symmetric Key:"+ str(encSymmKey))
                msg = sendSessionKey(encSymmKey)
                s.sendall(bytes(msg,'utf-8'))
                data = s.recv(1024).decode('utf-8')
                print (data)
                strStatus = "113 Nonce"
                if data and data.find(strStatus) < 0:
                        print("Invalid data received. Closing")
                else:
                        # Write code to parse received string and extract encrypted nonce
                        # from the server. The nonce has been encrypted with the server's
                        # private key.
                        u=data[10:]
                        print("Encrypted nonce: "+ u)
                        encNonce=int(u)#converts the parsed Encrypted Nonce to int
                        nonce = RSAdecrypt(encNonce, e, n)
                        print("Decrypted nonce: "+ str(nonce))
                        """Setting up for Simplified AES encryption"""
                        plaintext = nonce
                        simplified_AES.keyExp(symmetricKey) # Generating round keys for AES.
                        ciphertext = simplified_AES.encrypt(int(plaintext)) # Running simplified AES.
                        msg = sendTransformedNonce(ciphertext)
                        s.sendall(bytes(msg,'utf-8'))
                        data = s.recv(1024).decode('utf-8')
                        if data:
                                print(data)
                                print ("Enter prime numbers. One should be between 907 and 1013, and the other between 53 and 67")
                                Clientp = int(input('Enter P : '))#request user input for p
                                Clientq = int(input('Enter Q: '))#request user input for q
                                while (not isprime(Clientp) or not isprime(Clientq)):#prompt user if value not prime
                                        if not isprime(Clientp):print ("first number was not prime!!!")
                                        if not isprime(Clientq):print ("Second number was not prime!!!")
                                        print("")
                                        Clientp = int(input("Please enter a prime number between 907 and 1013: "))
                                        Clientq = int(input("Please enter a prime number between 53 and 67: "))
                                while (Clientp<907 or Clientp>1013) or (Clientq<53 or Clientq>67): # prompt user to re-enter prime
                                        if Clientp<907 or Clientp>1013 :print ("first number  Must Be greater Than 907 and less than 1013!!!")
                                        if Clientq<53 or Clientq>67:print ("Second number Must Be greater Than 53 and less than 67!!!")
                                        print("")
                                        Clientp = int(input("Please enter a prime number between 907 and 1013: "))
                                        Clientq = int(input("Please enter a prime number between 53 and 67: "))
                                clientN,clientE=genKeys(Clientp,Clientq)#uses the genKeys function to generate the public key 
                                msg="Client Public Key is :"+ str(clientN)+ " "+str(clientE)
                                s.sendall(bytes(msg,'utf-8'))#sends client's public key to server
                
        s.close()

if __name__ == "__main__":
    main()
