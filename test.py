import secrets
from SkinnyRFIDAuth import ReaderAuth,TagAuth


ID = secrets.randbits(96)
K = secrets.randbits(128)
FID = secrets.randbits(96)
K2 = secrets.randbits(128)


tag = TagAuth(ID,K,FID)
reader = ReaderAuth(ID,K,FID)

#Following should be successful
if reader.authRecv(tag.authRecv(reader.authInit(tag.authInit()))) == True:
    tag.authComplete(True)
    print("Success!")

#Following should be successful
if reader.authRecv(tag.authRecv(reader.authInit(tag.authInit()))) == True:
    tag.authComplete(True)
    print("Success!")

reader.key = K2
#Following should fail due to key mismatch
try:
    if reader.authRecv(tag.authRecv(reader.authInit(tag.authInit()))) == True:
        tag.authComplete(True)
except ValueError as e:
    print("Error!!")
