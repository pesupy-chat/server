from uuid import UUID
import asyncio
import pickle
from . import encryption as en

packet_map = {
    'CONN_INIT':
    'CONN_ENCRYPT_C':
    'SIGNUP':
    'S_CAPTCHA':
    'LOGIN':
    'CHAT_ENCRYPT_C':
    'AUTHENTICATE':
    'CREATE_ROOM':
    'CHAT_ACTION':
    'ALTER_ROOM':
    'LOGOUT':
}
class Handle():
    def __init__(self, type, data):
        
