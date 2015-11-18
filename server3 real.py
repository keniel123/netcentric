# Server to implement simplified RSA algorithm. 
# The server waits for the client to say Hello. Once the client says hello,
# the server sends the client a public key. The client uses the public key to
# send a session key with confidentiality to the server. The server then sends
# a nonce (number used once) to the client, encrypted with the server's private
# key. The client decrypts that nonce and sends it back to server encrypted 
# with the session key. 

# Author: fokumdt 2015-11-02

#!/usr/bin/python3

import socket
import random
import math
import hashlib
import time
import sys
import simplified_AES

def expMod(b,n,m):
	"""Computes the modular exponent of a number"""
	"""returns (b^n mod m)"""
	if n==0:
		return 1
	elif n%2==0:
		return expMod((b*b)%m, n/2, m)
	else:
		return(b*expMod(b,n-1,m))%m

def RSAencrypt(m, e, n):
    """Encryption side of RSA"""
    # Fill in the code to do RSA encryption
    c=modular_Exponentiation(m,e,n)
    return c

def RSAdecrypt(c, d, n):
        """Decryption side of RSA"""
        # Fill in the code to do RSA decryption
        m=modular_Exponentiation(c,d,n)
        return m

def gcd_iter(u, v):
    """Iterative Euclidean algorithm"""
    while v != 0:
        u, v = v, u % v
    return u

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

def modular_Exponentiation(a,b,n):
    x=1
    while(b>0):
        if (b&1==1):x=(x*a)%n
        a=(a*a)%n
        b >>= 1# represents binary conversion for example a >> = 15 (means 0000 1111)
    return x%n

def ext_Euclid(m,n):
    """Extended Euclidean algorithm"""
    # Provide the rest of the code to use the extended Euclidean algorithm
    # Refer to the project specification.
    A1,A2,A3=1,0,m
    B1,B2,B3=0,1,n
    while True:
        if B3==0:
            return A3
        if B3==1:
            return B2
        Q=math.floor(A3/B3)
        T1,T2,T3=A1-Q*B1,A2-Q*B2,A3-Q*B3
        A1,A2,A3=B1,B2,B3
        B1,B2,B3=T1,T2,T3


def generateNonce():
	"""This method returns a 16-bit random integer derived from hashing the
	    current time. This is used to test for liveness"""
	hash = hashlib.sha1()
	hash.update(str(time.time()).encode('utf-8'))
	return int.from_bytes(hash.digest()[:2], byteorder=sys.byteorder)

def genKeys(p, q):
     """Generate n, phi(n), e, and d."""
     # Fill in code to generate the server's public and private keys.
     # Make sure to use the Extended Euclidean algorithm.
     n=p*q#generates n by using the formula n=p*q
     phi=(p-1)*(q-1)#generates phi by using the formula phi=(p-1)*(q-1)
     e= random.randrange(1,phi)
     t=gcd_iter(e,phi)
     while t!=1:
        e=random.randrange(1,phi)#generates e such that the greatest common divisor of that number and phi is 1
        t=gcd_iter(e,phi)
     d=ext_Euclid(phi,e)#generates d by making the formula that d*e Mod phi =1
     while d<0:
             d+=phi
     return n,e,d,phi
	
def clientHelloResp(n, e):
    """Responds to client's hello message with modulus and exponent"""
    status = "105 Hello "+ str(n) + " " + str(e)
    return status

def SessionKeyResp(nonce):
    """Responds to session key with nonce"""
    status = "113 Nonce "+ str(nonce)
    return status

def nonceVerification(nonce, decryptedNonce):
    """Verifies that the transmitted nonce matches that received
       from the client."""
    if nonce==decryptedNonce:
        return "200 OK"
    else:
        return "400 Error Detected"
    #Enter code to compare the nonce and the decryptedNonce. This method
    # should return a string of "200 OK" if the parameters match otherwise
    # it should return "400 Error Detected"

HOST = ''                 # Symbolic name meaning all available interfaces
PORT = 9000               # Arbitrary non-privileged port
strHello = "100 Hello"
strHelloResp = "105 Hello"
strSessionKey = "112 SessionKey"
strSessionKeyResp = "113 Nonce"
strNonceResp = "130"
strServerStatus = ""
print("###############################Welcome To My Server######################################")
print ("Enter prime numbers. One should be between 907 and 1013, and the other\
 between 53 and 67")

p = int(input('Enter P : '))
q = int(input('Enter Q: '))
while (not isprime(p) or not isprime(q)):#prompt user if value not prime
        if not isprime(p):print ("first number was not prime!!!")
        if not isprime(q):print ("Second number was not prime!!!")
        print("")
        p = int(input("Please enter a prime number between 907 and 1013: "))
        q = int(input("Please enter a prime number between 53 and 67: "))

        
while (p<907 or p>1013) or (q<53 or q>67): # prompt user to re-enter prime 
        if p<907 or p>1013:print ("first number  Must Be greater Than 907 and less than 1013!!!")
        if q<53 or q>67:print ("Second number Must Be greater Than 53 and less than 67!!!")
        print("")
        p = int(input("Please enter a prime number between 907 and 1013: "))
        q = int(input("Please enter a prime number between 53 and 67: "))
        
# You should delete the next three lines. They are included so your program can
# run to completion

n,e,d,phi= genKeys(p, q)#function call to generate keys and assign values to n,e,d,phi
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# The next line is included to allow for quicker reuse of a socket.
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(1)
conn, addr = s.accept()
print('Connected by', addr)
data = conn.recv(1024).decode('utf-8')
print (data)
if data and data.find(strHello) >= 0:
	msg = clientHelloResp(n, e)
	conn.sendall(bytes(msg,'utf-8'))
	data = conn.recv(1024).decode('utf-8')
	print (data)
	if data and data.find(strSessionKey) >= 0:
		# Add code to parse the received string and extract the symmetric key
		a=data[15:]
		symmkey=int(a)#converts the parsed symmetric key to a integer
		print ("D:" + str(d))#print the value for d
		print ("N:" + str(n))#print the value for n
		print ("E:"+ str(e))#print the value for e
		print ("PhiN:"+ str(phi))#print the value for phi(N)
		SymmKey = RSAdecrypt(symmkey,d,n)# Make appropriate function call to decrypt the symmetric key
		print ("Decrypted Symmetric Key:" +str(SymmKey))
		# The next line generates the round keys for simplified AES
		simplified_AES.keyExp(int(SymmKey))
		challenge = generateNonce()#the value returned from calling generateNonce() is assigned to the challenge variable
		print ("Challenge:" + str(challenge))#print generated nonce
		msg = SessionKeyResp(RSAdecrypt(challenge,d, n))
		print ("Encrypted Nonce:"+str(msg))#printing of encrypted nonce
		conn.sendall(bytes(msg,'utf-8'))
		data = conn.recv(1024).decode('utf-8')
		if data and data.find(strNonceResp) >= 0:
			# Add code to parse the received string and extract the nonce
			encryptedChallenge=int(data[4:])
			# The next line runs AES decryption to retrieve the key.
			decryptedNonce = simplified_AES.decrypt(encryptedChallenge)
			msg = nonceVerification(challenge, decryptedNonce)# Make function call to compare the nonce sent with that received
			
			conn.sendall(bytes(msg,'utf-8'))
			data = conn.recv(1024).decode('utf-8')#the server recieves the client's public key
			print (data)#the server prints the client's public key
conn.close()
