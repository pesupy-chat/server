from uuid import UUID
import asyncio
import pickle
from . import encryption as en

class Handle():
    def __init__(self, type, data):
        
