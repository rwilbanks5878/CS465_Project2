#
# Name: Rachel Wilbanks
# Program Name: partyA.py
# Finish Date: 7/13/2025
#
#partyA.py intends to connect to Party B over a socket (localhost),
#          exchange certificates, perform confirm identities (w/RSA),
#          and send a signed session key.
#          It works together with partyB.py (as you can probably
#          already tell) and a root.


from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
import socket
import ssl
import os


session_key = b"CURRENTKEY5555"


with open("partyA.key", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password = None     #No password is needed
    )


with open("partyA.crt", "rb") as cert_file:
    the_cert = x509.load_pem_x509_certificate(cert_file.read())


with open("rootCA.pem", "rb") as root_file:
    root_cert = x509.load_pem_x509_certificate(root_file.read())


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect(("localhost", 12345))
print("Successfully connected to Party B")


s.send(the_cert.public_bytes(serialization.Encoding.PEM))

# Get B's cert
b_cert_data = s.recv(1024)
b_certificate = x509.load_pem_x509_certificate(b_cert_data)

#Verify B_cert using root
try:
    root_cert.public_key().verify(
        b_certificate.signature,
        b_certificate.tbs_certificate_bytes,
        padding.PKCS1v15(),
        b_certificate.signature_hash_algorithm
    )

    print("Party B's certificate has been verified!")

except:
    print("Verification failed (for B)")
    s.close()
    exit()


n1 = b"ABCDEF1234567890"
identify_a = b"A"        #A Identity
message = n1 + identify_a

#print("A is sending message of length:", len(message))
#^for ciphertext length error


b_public = b_certificate.public_key()
encrypted_message = b_public.encrypt(n1 + identify_a, padding.PKCS1v15())


s.send(encrypted_message)


data = s.recv(128) #Get B response


response = private_key.decrypt(data, padding.PKCS1v15())
n1_returned = response[:16]
n2 = response[16:]
#^1st 16 bytes = N1; Next 16 bytes = N2^ (for n1_returned and n2)


#Check if N1 is the same as before (if it is)
if n1_returned == n1:
    print("N1 has been verified. We've gotten N2.")

else:
    print("N1 does not match.")
    s.close()
    exit()


#Encrypt N2, send to B. Sign session
encrypt_n2 = b_public.encrypt(n2, padding.PKCS1v15())
s.send(encrypt_n2)


signature = private_key.sign(
    session_key,
    padding.PKCS1v15(),
    hashes.SHA256()
)


#encrypted_signature = b_public.encrypt(signature, padding.PKCS1v15())
#^Not needed anymore (I think)

s.send(signature)

#Finished if this is able to print (finally was able to reach)
print("The Session key has been sent.")

s.close()
