from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives import serialization  
from cryptography.hazmat.primitives.asymmetric import rsa  
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA



def save_file(filename, content):  
   f = open(filename, "wb")  
   f.write(content)
   f.close()  
  
 
def generate_key (): 
    
    print ("----- Generating your keys, please wait -----")
    private_key = rsa.generate_private_key( 
        public_exponent=65537,  
        key_size=2048,  
        backend=default_backend()  
    )  


    pem = private_key.private_bytes(  
        encoding=serialization.Encoding.PEM,  
        format=serialization.PrivateFormat.PKCS8,  
        encryption_algorithm=serialization.NoEncryption()  
    )  
    save_file("private.pem", pem)  
    

    public_key = private_key.public_key()  
    pem = public_key.public_bytes(  
        encoding=serialization.Encoding.PEM,  
        format=serialization.PublicFormat.SubjectPublicKeyInfo  
    )  
    save_file("public.pem", pem) 
    print ("----- Your keys are now generated and saved ! -----")
    print ("----- Please check the files Private.pem and Public.pem -----")

def message_encrypt () :
    
    input1 = input ("Please enter your message :")
    message = input1.encode()
    key = RSA.import_key(open('public.pem').read())
    cipher = PKCS1_OAEP.new(key)
    ciphertext=cipher.encrypt(message)
    f= open ("encrypted_message.txt","wb")
    f.write(ciphertext)
    f.close()
    print ("----- ENCRYPTING -----")            
    print ("----- Your message is now encrypted with RSA and saved ! -----")
    print ("----- Please check the file encrypted_message.txt -----")

def message_decrypt () : 
    
    print ("----- DECRYPTING -----")
    key = RSA.import_key(open('private.pem').read())
    with open("encrypted_message.txt", "rb") as file:
        ciphertext = file.read()
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)
    print (f"----- Your message is : {plaintext.decode('utf-8')} -----")
   


def sign_message():
    
    message = input ("Enter the message to sign: ")
    
    with open("private.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    
    signature = private_key.sign(
        message.encode('utf-8'),  
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    f = open ("signature.txt", "wb")
    f.write(signature)
    f.close
    print ("----- Your message is now SIGNED with RSA and saved ! -----")
    print ("----- Please check the file signature.txt -----")


def verify_signature():
    
    message = input ("Enter the message that was signed: ")
    
    with open("public.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
        
    with open("signature.txt", "rb") as file:
        signature = file.read()

    try:
        public_key.verify(
            signature,
            message.encode('utf-8'),  
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print ("----- Signature is valid! ------")  
       
    except:
        print ("------ Signature is INVALID! :( ------")
        