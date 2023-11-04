import hashlib
import re 
import maskpass
import random
import string

def register ():

    file1 = open(r"enregistrement.txt","a")

    regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')

    while True:
        email = input ("Veuillez entrer votre adresse e-mail : ")
        if re.fullmatch(regex,email) :
            break
        else :
               print("----- Choix invalide. Veuillez réessayer. -----")
        


    print ("---- Choisissez la méthode de création de mot de passe -----")
    print ("1 - Fournissez votre propre mot de passe ")
    print ("2 - Generer a random password.")
    choice = input(" Please choose method 1 or 2 : ")
        
    while True:
        
        match choice :
            case '1':

        
            
                while True :
                    
                    flag = -1
                    password = maskpass.askpass(mask="*")   
                    if (len(password)<=8):
                        flag = -1
                        break
                    elif not re.search("[a-z]", password):
                        flag = -1
                        break
                    elif not re.search("[A-Z]", password):
                        flag = -1
                        break
                    elif not re.search("[0-9]", password):
                        flag = -1
                        break
                    elif not re.search("[_@$]" , password):
                        flag = -1
                        break
                    else:
                        flag = 0
                        break
                if flag == 0 :
        
                        print ("------ FÉLICITATIONS ! Vous êtes maintenant enregistré(e) ! ------")
                        print ("\n")
                       
                        break                      
                else :

                        print ("***  Le mot de passe ne correspond pas aux critères (8 caractères, MAJUSCULES, Symboles _@$) ! ***")
                
            case '2':
                

                    
                SYMB = ['@', '#', '$', '?', '.','*']

                one = random.choice(string.digits) + random.choice(string.ascii_letters) +random.choice(SYMB)
                two = random.choice(string.digits) + random.choice(string.ascii_letters) +random.choice(SYMB)
                first_password = one + two 
                gen_password = list(first_password)
                random.shuffle(gen_password)
                str1= ""
                password= str1.join(gen_password)
                print ("------- Génération de votre mot de passe, veuillez patienter -------- ")
        
            
                print(" ** Votre mot de passe généré est : " , str1.join(gen_password), "Please make sure to save it somewhere safe. **")
                
                break
            
            case default :
                print ("** Veuillez taper 1 ou 2 pour faire un choix ! ** ")
                
    hashed_password= hashlib.sha256(password.encode()).hexdigest()
    file1.write(email)
    file1.write("---")
    file1.write(hashed_password)
    file1.write("\n")
    file1.close()

def login () :
    print ("----- Entrez vos identifiants pour vous connecter ! -----")
    print ("\n")
    

    while True:
        
        
        log = input ("Entrez votre adresse e-mail : ")
        pwd = maskpass.askpass(mask="*")   
        hashed_pwd= hashlib.sha256(pwd.encode()).hexdigest()
        compare = log+"---"+hashed_pwd


        file1 = open(r"enregistrement.txt","r")
        x = 0 
        for logins in file1 :
            if (compare == logins.strip()) : 
                x = 1

                
                
        if x == 1 :
            print ("Connexion en cours, veuillez patienter -----")
            
            break
        else :
            print ("----- Connexion en cours, veuillez patienter -----")
            print ("----- Adresse e-mail ou mot de passe INCORRECT, veuillez réessayer ! -----")
         
            
            




