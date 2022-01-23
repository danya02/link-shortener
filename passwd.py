import hashlib
import getpass
import secrets
import hmac

def hash_password(pw, salt):
    password = pw.encode()
    key = hashlib.scrypt(password, salt=salt, n=8192, p=1, r=8, dklen=32)
    return key

def gen_stored(pw):
    salt = secrets.token_bytes(16)
    hash = hash_password(pw, salt)
    return hash.hex() + '|' + salt.hex()

def check_password_against_stored(pw, stored):
    hash, salt = stored.split('|')
    hash = bytes.fromhex(hash)
    salt = bytes.fromhex(salt)
    return hmac.compare_digest(hash, hash_password(pw, salt))

if __name__ == '__main__':
    print(gen_stored(getpass.getpass()))
