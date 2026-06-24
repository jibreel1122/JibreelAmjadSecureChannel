import math

constant1=0x61707865
constant2=0x3320646e
constant3=0x79622d32
constant4=0x6b206574
max_int=0xffffffff
constants=[constant1,constant2,constant3,constant4]

def rotl(x,n):
    return ((x<<n)|(x>>(32-n)))&max_int

def Qround(a,b,c,d):
    a=(a+b)&max_int
    d^=a
    d=rotl(d,16)

    c=(c+d)&max_int
    b^=c
    b=rotl(b,12)

    a=(a+b)&max_int
    d^=a
    d=rotl(d,8)

    c=(c+d)&max_int
    b^=c
    b=rotl(b,7)
    return a,b,c,d

def inner_block(state):
    state[0],state[4],state[8],state[12]=Qround(state[0],state[4],state[8],state[12])
    state[1],state[5],state[9],state[13]=Qround(state[1],state[5],state[9],state[13])
    state[2],state[6],state[10],state[14]=Qround(state[2],state[6],state[10],state[14])
    state[3],state[7],state[11],state[15]=Qround(state[3],state[7],state[11],state[15])
    state[0],state[5],state[10],state[15]=Qround(state[0],state[5],state[10],state[15])
    state[1],state[6],state[11],state[12]=Qround(state[1],state[6],state[11],state[12])
    state[2],state[7],state[8],state[13]=Qround(state[2],state[7],state[8],state[13])
    state[3],state[4],state[9],state[14]=Qround(state[3],state[4],state[9],state[14])

def serialize(state):
    return b''.join(word.to_bytes(4,'little') for word in state)

def chacha20_block(key,counter,nonce):
    key_words=[int.from_bytes(key[i:i+4],'little')for i in range(0,32,4)]
    nonce_words=[int.from_bytes(nonce[i:i+4],'little')for i in range(0,12,4)]
    state=constants+key_words+[counter]+nonce_words
    initial_state=state.copy()
    for i in range(10):
        inner_block(state)
    for i in range(16):
        state[i]=(state[i]+initial_state[i])&max_int
    return serialize(state)
def chacha20_encrypt(key,counter,nonce,plaintext):
    encrypted_message=b""
    for j in range(len(plaintext)//64):
        key_stream=chacha20_block(key,counter+j,nonce)
        block=plaintext[j*64:j*64+64]
        encrypted_message+=bytes(a^b for a,b in zip(block,key_stream))
    if((len(plaintext)%64)!=0):
        j=len(plaintext)//64
        key_stream=chacha20_block(key,counter+j,nonce)
        block=plaintext[j*64:]
        encrypted_message+=bytes(a^b for a,b in zip(block,key_stream))
    return encrypted_message

def chacha20_decrypt(key,counter,nonce,ciphertext):
    return chacha20_encrypt(key,counter,nonce,ciphertext)