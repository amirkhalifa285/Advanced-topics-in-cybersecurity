from zoodb import *
from debug import *

import hashlib
import random

def newtoken(db, cred):
    hashinput = "%s%.10f" % (cred.password, random.random())
    cred.token = hashlib.md5(hashinput.encode('utf-8')).hexdigest()
    db.commit()
    return cred.token

def login(username, password):
    db = cred_setup()
    cred = db.query(Cred).get(username)
    if not cred:
        return None
    if cred.password == password:
        return newtoken(db, cred)
    else:
        return None

def register(username, password):
    creddb = cred_setup()
    cred = creddb.query(Cred).get(username)
    if cred:
        return None
    
    persondb = person_setup()
    person = persondb.query(Person).get(username)
    if person: # If a Person entry already exists, don't create new Cred
        return None

    newcred = Cred()
    newcred.username = username
    newcred.password = password
    creddb.add(newcred)
    creddb.commit()

    # Create a corresponding Person entry for non-authentication data
    newperson = Person()
    newperson.username = username
    persondb.add(newperson)
    persondb.commit()
    
    return newtoken(creddb, newcred)

def check_token(username, token):
    db = cred_setup()
    cred = db.query(Cred).get(username)
    if cred and cred.token == token:
        return True
    else:
        return False

    
