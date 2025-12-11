import rpclib

def login(username, password):
    with rpclib.client_connect('/authsvc/sock') as client:
        return client.call('login', username=username, password=password)

def register(username, password):
    with rpclib.client_connect('/authsvc/sock') as client:
        return client.call('register', username=username, password=password)

def check_token(username, token):
    with rpclib.client_connect('/authsvc/sock') as client:
        return client.call('check_token', username=username, token=token)