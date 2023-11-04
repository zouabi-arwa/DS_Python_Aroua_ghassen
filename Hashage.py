import hashlib
import bcrypt
import maskpass

def create_word ():
   word = maskpass.askpass ("Veuillez entrer un mot à utiliser. : ",mask="*")
   f = open ("word1.txt","w")
   f.write (word)
   f.close
   print ("----- Votre mot de passe est maintenant créé et sauvegardé ! -----")
   print ("\n")
   
def sha256 ():
    f =open ("word1.txt","r")
    word = f.read()
    hashed_word = hashlib.sha256(word.encode()).hexdigest()
    f1 = open ("hashed256.txt","w")
    f1.write(hashed_word)
    f1.close()
    print ("\n")
    print ("----- haché avec SHA-256 et enregistré.! -----")
    print ("-----Veuillez vérifier le fichier hashed256.txt -----")
    
def salt_bcrypt() :
    
    f = open ("hashed256.txt","r")
    word = f.read().encode() 

    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(word, salt)
    f1 = open ("bcrypted_salt.txt", "wb")
    f1.write (hashed)
    f1.close
    print ("\n")
    print ("----- Your word is now hashed with a salt and saved ! -----")
    print ("------Veuillez vérifier le fichier bcrypted_salt.txt -----")
                
    
def dictionary_attack():
    print ("\n")
    print ("---- Veuillez patienter pendant que nous recherchons votre mot de passe.----- ")
    print ("\n")
    dictionary = ["mot1", "mot2", "mot3", "mot4", "mot5"]
    print("Attaquer par dictionnaire")
    for word in dictionary:
     hashed_word = hashlib.sha256(word.encode()).hexdigest()
    if hashed_word == hashed_word:
     print(f"Mot trouvé dans le dictionnaire : {word}")
           
    else:
      print("Aucun mot du dictionnaire ne correspond.")
                        
                
            

