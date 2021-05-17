from server_security_utils import authenticate, get_clients_public_key
import hashlib

def get_user_credentials():
    return "amit", "1234"

def send_symetric_key_to_user(twofish_key_encrypted_signed):
    print(f"Send to user twofish key, encrypted and signed: {twofish_key_encrypted_signed}")

def send_user_encrypted(msg):
    encrypted_message = twofish.encrypt(msg, twofish_key)
    print(f"Send encrypted data to user: {encrypted_message}")

def get_choice_from_user():
    pass
    #return twofish.encrypt("1", twofish_key)

def get_user_encrypted_message():
    user_encrypted_message = get_choice_from_user()
    return twofish.decrypt(user_encrypted_message, twofish_key)

def send_user_options():
    menu = '''
    [1] for uploading new table entry
    [2] get entry from table
    '''
    print("Send to user:")
    send_user_encrypted(menu)

def main():
    username, password = get_user_credentials()
    print(f"username = {username}, password = {password}")

    if not authenticate(username, password):
        raise ValueError("Wrong Credentials!")
    
    print("Successful Login!")
    
    # Successfull login
    user_public_key = get_clients_public_key(username)
    print(f"user_public_key (e, n) = {user_public_key}")

    twofish_key_encrypted = rsa.encrypt(user_public_key, twofish_key)
    twofish_key_encrypted_signed = el_gamal_signature.sign(twofish_key_encrypted)
    send_symetric_key_to_user(twofish_key_encrypted_signed)

    # From now on every message between the client and server will be encrypted
    send_user_options()
    choice = get_user_encrypted_message()

    if choice == "1":
        id = get_user_encrypted_message()
        name = get_user_encrypted_message()
        database.update_table(name)

    elif choice == "2":
        id = get_user_encrypted_message()
        name = database.get_entry_by_id(id)
        send_user_encrypted(name)


if __name__ == "__main__":
    main()