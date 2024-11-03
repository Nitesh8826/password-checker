#The requests module allows you to send HTTP requests using Python.
import requests 

#using inbuilt sha1 encryption in order to keep the pasword to us only
import hashlib  


#using sys to make use of command line arguments 
import sys #this is my import



#function to make https request to the api of pwnedpasswords
#with first5char of our generated sha1
#response is recorded 
#status is checked if it is 200 , it is good 
def request_api_data(query_char):

    url = "https://api.pwnedpasswords.com/range/"+query_char
    res = requests.get(url)  
    if (res.status_code != 200):
        raise RuntimeError(
            f'Error fetching: {res.status_code},chech the api and try again')
    return res





#catching the hashes (As tail : occurence in database)  as h and c    

#the tail occurence is compared with the tail we generated using module sha1 hashlib

#if matched return the count to the calling function


def get_pass_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, c in hashes:
        if h == hash_to_check:
            return c
    return 0



#function to catch the response after requesting the api with first 5 char of our generated sha1
#and calling get_pass_leaks_count() function with arguments :response from website and tail we generated

def pwned_api_check(password): 
    # check pass if it exists in API response

    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()  #encrypt in sha1
    first5_char, tail = sha1pass[:5], sha1pass[5:]                          
    response = request_api_data(first5_char)
    return get_pass_leaks_count(response, tail)    



#driver function 

def main(args): 
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'\n\n{password} was found {count} times...you should probably change it\n')
            print()
        else: 
            print(f'\n\n{password} is safe!!\n\n')
    return 'done!!!'



#if it is the current file 

if __name__=='__main__':

    

    print('What a strong password should be:')
    print('A strong password would be Between eight and 64 characters, depending on the allowed length')
    print('Contain at least three, but preferably all, of the following:\nUppercase letter')
    print('Lowercase letter')
    print('Number')
    print('Special character')

    sys.exit(main(sys.argv[1:]))
 


