from OpenSSL import crypto
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend  
from cryptography import x509


def cert_gen(
    emailAddress="zouebiiaroua11@gmail.com",
    commonName="Arwazouabi",
    countryName="TN",
    organizationName="Tekup",
    serialNumber=0,
    validityStartInSeconds=0,
    validityEndInSeconds=10*365*24*60*60,
    KEY_FILE = "private.key",
    CERT_FILE="signed.crt"):
    
    
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    
    
    
    cert = crypto.X509()
    cert.get_subject().C = countryName
    cert.get_subject().O = organizationName
    cert.get_subject().CN = commonName
    cert.get_subject().emailAddress = emailAddress
    cert.set_serial_number(serialNumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    with open(CERT_FILE, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(KEY_FILE, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))
    print ("----- Votre certification est créée-----")
    print ("-----  Veuillez vérifier le fichier signed.crt-----")



def encrypt_w_cert () :
    with open("signed.crt","rb") as cert_file:
        certificate = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
    public_key = certificate.public_key()
    
    
    message1 = input ("Entrez votre message ici: ")
    message = message1.encode()

    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    f =open ("encrypted_w_cert.txt","wb")
    f.write(encrypted_message)
    f.close
    print ("\n")
    print ("----- Votre message est en cours de chiffrement-----")

    
    print ("----- Votre message a été chiffré avec le certificat auto-signé -----")
    print ("----- Veuillez vérifier le fichier encrypted_w_cert.txt ------")
  
    
def decrypt_w_cert():

    with open("private.key", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    with open("encrypted_w_cert.txt", "rb") as encrypted_file:
        encrypted_message = encrypted_file.read()

    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print ("---- DÉCRYPTAGE DE VOTRE MESSAGE MAINTENANT EN UTILISANT LE CERTIFICAT AUTO-SIGNÉ ----")
    print ("\n")
    print ("---- Veuillez patienter. -----")
    print(f"----- Votre message est : {decrypted_message.decode()} -----")
   
    
