from Hashage import create_word
from Hashage import sha256
from Hashage import salt_bcrypt
from Hashage import dictionary_attack
from PASS import register
from PASS import login
from RSA import generate_key 
from RSA import message_encrypt
from RSA import message_decrypt
from RSA import sign_message
from RSA import verify_signature
from Certificat import cert_gen
from Certificat import encrypt_w_cert
from Certificat import decrypt_w_cert



def Menu_Principal():
    print("******* 1 - Hash *******")
    print("******* 2 - RSA *******")
    print("******* 3 - Certificat *******")
    print("******* 0 - Revenir au menu principal*******")
    
def main_menu():
    print("1 -Enregistrement")
    print("2 - authentification")
    print("0 - Quitter")

def hash_menu():
    print("1 - Donnez un mot à haché (en mode invisible)")
    print("a- Haché le mot par sha256 ")
    print("b- Haché le mot en générant un salt (bcrypt)")
    print("c- Attaquer par dictionnaire le mot inséré")
    print("d - Revenir au menu principal")

def rsa_menu():
    print("a- Générer les paires de clés dans un fichier")
    print("b- Chiffrer un message de votre choix par RSA")
    print("c- Déchiffrer le message (b)")
    print("d- Signer un message de votre choix par RSA")
    print("e- Vérifier la signature du message (d)")
    print("f- Revenir au menu principal")
    
def certif_menu():
    print("a- Generate Autosigned Certificate with RSA")
    print("b- Encrypt a message with your Certificate")
    print("c- Decrypt the message")
    print("d- Revenir au menu principal")

def main():
    while True:
        main_menu()
        choice = input("Enter votre choix : ")

        if choice == '1':
            while True:
              
                register()
                
                break

        elif choice == '2':
            while True:
                   
                login()
                Menu_Principal()
                login_choice = input("Enter votre choix : ")

                if login_choice == '1':
                    
                    while True:
                        
                        hash_menu()
                        
                        hash_choice = input("Enter votre choix : ")

                        if hash_choice == '1':
                            create_word()
                            

                        elif hash_choice == 'a':
                            sha256()

                        elif hash_choice == 'b':
                            
                            salt_bcrypt()
                            
                        elif hash_choice == 'c':
                            
                            dictionary_attack()

                        elif hash_choice == 'd':
                            break

                        else:
                           print("----- Choix invalide. Veuillez réessayer. -----")

                elif login_choice == '2':
                    
                    while True:
                        
                        rsa_menu()
                        
                        rsa_choice = input("Enter votre choix : ")

                        if rsa_choice == 'a':
                            generate_key()
                        elif rsa_choice == 'b':
                            message_encrypt()
                        elif rsa_choice == 'c':
                            message_decrypt()
                        elif rsa_choice == 'd':
                            sign_message()
                        elif rsa_choice == 'e':
                            verify_signature()
                        elif rsa_choice == 'f':
                            
                            break

                        else:
                            print("----- Choix invalide. Veuillez réessayer. -----")
                            
                elif login_choice == '3':
                    
                    while True:
                        certif_menu()
                        certif_choice = input("Enter votre choix : ")

                        if certif_choice == 'a':
                            cert_gen()
                        elif certif_choice == 'b':
                            encrypt_w_cert()
                        elif certif_choice == 'c':
                            decrypt_w_cert()

                        elif certif_choice == 'd':
                            break

                        else:
                            print("----- Choix invalide. Veuillez réessayer. -----")
                        

                elif login_choice == '0':
                    break

                else:
                    print ("----- Choix invalide. Veuillez réessayer. -----")

        elif choice == '0':
            print("----- Quittez le programme. Au revoir ! -----")

            break

        else:
            print ("----- Choix invalide. Veuillez réessayer. -----")

if __name__ == '__main__':
    main()


