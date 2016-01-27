import uuid
import hashlib


def hash_password(password):
    salt = uuid.uuid4().hex
    return (hashlib.sha512(password + salt).hexdigest(), salt)

def validate_password_hash(password, salt, password_hash):
    return hashlib.sha512(password + salt).hexdigest() == password_hash
