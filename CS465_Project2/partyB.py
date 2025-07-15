#
# Name: Rachel Wilbanks
# Program Name: partyB.py
# Finish Date: 7/13/2025
#
#partyB.py intends to confirm identities using RSA-based mutual
#          authentication using public keys and certificates. It is given a
#          session key from Party A and verifies it using a signature.
#          It works together with partyA.py (as you can probably
#          already tell) and a root.


from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
import socket
import ssl
import os


session_key = b"CURRENTKEY5555"


with open("partyB.key", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password = None     #No password is needed for this key
    )

#Party B Cert. (end to A for verification)
with open("partyB.crt", "rb") as cert_file:
    the_cert = x509.load_pem_x509_certificate(cert_file.read())


#Root Cert. (for A certificate verification)
with open("rootCA.pem", "rb") as root_file:
    root_cert = x509.load_pem_x509_certificate(root_file.read())


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.bind(("localhost", 12345))

#Have partyB.py wait for partyA.py connection
s.listen(1)
print("Waiting for connection...")
conn, addr = s.accept()
print(f"Connected by {addr}")


#Get A's certificate, then send B's certificate to A
a_cert_bytes = conn.recv(1024)
a_certification = x509.load_pem_x509_certificate(a_cert_bytes)

conn.send(the_cert.public_bytes(serialization.Encoding.PEM))


#Verify A's cert using root CA
try:
    root_cert.public_key().verify(
        a_certification.signature,
        a_certification.tbs_certificate_bytes,
        padding.PKCS1v15(),
        a_certification.signature_hash_algorithm
    )

    print("Party A's certificate has been verified!")

except:
    print("Certificate verification failed.")
    conn.close()
    exit()


data = conn.recv(128)

#print("B received ciphertext of length:", len(data))
#for ciphertext error (solved/no longer needed)

#Decrypt w/B to get N1 and A's identity
decrypted = private_key.decrypt(data, padding.PKCS1v15())
n1 = decrypted[:16]
id_a = decrypted[16:]


n2 = b"ZYXWVUTSRQPONMLK"


#Encrypt N1 + N2 and send back
a_public = a_certification.public_key()
enc_n1_n2 = a_public.encrypt(n1 + n2, padding.PKCS1v15())
conn.send(enc_n1_n2)

enc_n2 = conn.recv(128)
#Decrypt with B's private key. check if match w/earlier N2
n2_return = private_key.decrypt(enc_n2, padding.PKCS1v15())

if n2_return == n2:
    print("N2 has been verified.")

else:
    print("N2 mismatched!")
    conn.close()
    exit()


#Get final from A (contains session key)
final = conn.recv(128)

#signed_key = private_key.decrypt(final, padding.PKCS1v15())
signed_key = final

try:
    a_public.verify(
        signed_key,
        b"CURRENTKEY5555",
        #session_key
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    print("Session key verified.")

except:
    print("Session key verification failed.")

conn.close()


