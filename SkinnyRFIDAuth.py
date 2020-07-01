"""
RFID Auth protocol based on https://eprint.iacr.org/2016/660.pdf
Author: Abhishek Shingane
Date: 1-July-2020


TODO
    [ ] Implement fallback FID and Key in case of desynchronization attack : Refer page-5 para-4 of researchpaper
    [ ] Initialisation of FID
    [ ] Implement save state function to save ID,K,FID,FID_OLD,K_OLD on reader
    [ ] Exception handling
"""


import secrets #for randbits
# Custom modules
from SkinnyCipher import SkinnyCipher

def keyPermutation(key):
    keyHex = format(key,'X')

    # Key length can be less than 32
    # This will create problem in permutation therefore we prepend zeros
    if len(keyHex) < 32:
        extraBytes = 32 - len(keyHex)
        prependStr = '0'*extraBytes
        keyHex = prependStr + keyHex

    #split the keyHex string in 2 byte units and save 2 bytes in one node.
    keyArray = [keyHex[i:i+2] for i in range(0, len(keyHex), 2)]

    permutation =[9,15,8,13,10,14,12,11,0,1,2,3,4,5,6,7] # refer to the research paper for values
    permutedKeyHexStr = ''

    #Append the permutaion in correct order
    for i in range(0,16):
        permutedKeyHexStr = permutedKeyHexStr + keyArray[permutation[i]]

    permutedKeyDec =  int(permutedKeyHexStr,16)

    return permutedKeyDec


class ReaderAuth:
    id = None
    key = None
    keyOld = None
    fid = None
    fidOld = None
    m1 = None
    m2 = None
    rand = None

    def __init__(self,id,key,fid,keyOld=None,fidOld = None):
        self.id = id
        self.key = key
        self.fid = fid
        self.fidOld = fidOld
        self.keyOld = keyOld

    def authInit(self,fid):

        if self.fid != fid:
            raise ValueError

        self.rand = secrets.randbits(96)
        self.m1 = self.fid ^ self.rand

        cipher = SkinnyCipher(self.key)
        self.m2 = cipher.encrypt(self.fid ^ self.id ^ self.rand)
        
        # format(int,'X') returns hex string without 0x appended. 
        return format(self.m1,'X')+" "+format(self.m2,'X')

        
    def authRecv(self,m3P): 

        cipher = SkinnyCipher(self.key)
        m3 = cipher.encrypt(self.m2 ^ self.rand) 

        if m3P == m3:

            #Update replace fidOld , keyOld with current fid and key. Generate new key
            self.fidOld = self.fid
            self.keyOld = self.key
            self.fid = self.m1
            self.key = keyPermutation(self.key)
            
            #Authentication on reader complete and succesfull 
            return True
        else:
            raise ValueError
            
class TagAuth:

    id = None 
    fid = None
    key = None
    m1 = None

    def __init__(self,id,key,fid):

        # ID and fid are 96-bit, K is 128-bit. fid and K are updated after each authentication
        self.id = id
        self.key = key
        self.fid = fid


    def authInit(self):
        return self.fid

    def authRecv(self,message):
        #message: m1 || " " || m2

        messageList = message.split(" ")
        self.m1 = int(messageList[0],16)
        m2 = int(messageList[1],16)
        rP = self.m1 ^ self.fid

        cipher = SkinnyCipher(self.key)
        m2P = cipher.encrypt(self.fid ^ self.id ^ rP) 

        if m2 == m2P:
            return cipher.encrypt(m2P ^ rP)  
        else:
            raise ValueError
            

    def authComplete(self,status=False):

        if status == False:
            # Authentication on reader failed. 
            raise ValueError
        
        #Update fid and key
        self.fid = self.m1
        self.key = keyPermutation(self.key)

        #Authentication successful and complete
        return True
        


