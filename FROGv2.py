def FROG_ecrypt(plainText,internKey,blockSize=16):
    cipherText=[]
    for i in plainText:
        a=ord(i)
        cipherText.append(a)
    fragmentCipherText=[]
    i=0
    while i<len(cipherText):
        fragmentCipherText.append(cipherText[i:i+16])
        i+=16
    j=len(fragmentCipherText)
    i=len(fragmentCipherText[j-1])
    while i<16:
        fragmentCipherText[j-1].append(32)
        i+=1

    j=0
    while j<len(fragmentCipherText):
        iteration=0
        while iteration<8:
            i=0
            while i<blockSize:
                fragmentCipherText[j][i]^=internKey[iteration][0][i]
                fragmentCipherText[j][i]=internKey[iteration][1][fragmentCipherText[0][i]]
                if i<15:
                    fragmentCipherText[j][i+1]^=fragmentCipherText[j][i]
                else:
                    fragmentCipherText[j][0]^=fragmentCipherText[j][i]
                k=internKey[iteration][2][i]
                fragmentCipherText[j][k]^=fragmentCipherText[j][i]
                i+=1

            iteration+=1
            i=0
        j+=1
        iteration=0
    return fragmentCipherText

def FROG_decrypt(plainText,internKey):
    cipherText=[]
    for i in plainText:
        a=ord(i)
        cipherText.append(a)
    fragmentCipherText=[]
    i=0
    while i<len(cipherText):
        fragmentCipherText.append(cipherText[i:i+16])
        i+=16
    j=len(fragmentCipherText)
    i=len(fragmentCipherText[j-1])
    while i<16:
        fragmentCipherText[j-1].append(32)
        i+=1

    j=0
    while j<len(fragmentCipherText):
        iteration=7
        while iteration>=0:
            i=15
            while i>=0:
                k=internKey[iteration][2][i]
                fragmentCipherText[j][k]^=fragmentCipherText[j][i]
                if i<15:
                    fragmentCipherText[j][i+1]^=fragmentCipherText[j][i]
                else:
                    fragmentCipherText[j][0]^=fragmentCipherText[j][i]
                fragmentCipherText[j][i]=internKey[iteration][1].index(fragmentCipherText[0][i])
                fragmentCipherText[j][i]^=internKey[iteration][0][i]
                i-=1
            iteration-=1
            i=15
        j+=1
        iteration=7

    return fragmentCipherText

def makeInternalKey(internKey,isdecr=False):
    resultKey=[]
    i=0
    while i<len(internKey)/288:
        resultKey.append([internKey[i:i+16],internKey[i+16:i+272],internKey[i+272:i+288]])
        i+=1
    internKey=resultKey
    i=0
    while i<8:
        internKey[i][1]=makePermutation(internKey[i][1],255)
        if isdecr:
            internKey[i][1].reverse()
        internKey[i][2]=makePermutation(internKey[i][2])
        validate(internKey[i][2])
        i+=1
    return internKey

def hashKey(userKey,randomSeed):
    #Step a
    simpleKey=[]
    keyLen=len(userKey)
    while len(userKey)<2304 or len(randomSeed)<2304:
        userKey+=userKey
        randomSeed+=randomSeed
    userKey=userKey[:2304]
    randomSeed=randomSeed[:2304]
    S=0
    K=0
    i=0
    while i<2304:
        simpleKey.append(randomSeed[S]^userKey[K])
        if S<250:
            S+=1
        else:
            S=0
        if K<keyLen-1:
            K+=1
        else:
            K=0
        i+=1
    simpleFROGinternKey=makeInternalKey(simpleKey)

    #Step b
    buffer=[]
    i=0
    while i<16:
        buffer.append(0)
        i+=1
    last=keyLen-1
    if last>=16:
        last=16-1
    i=0
    while i<last:
        buffer[i]^=userKey[i]
        i+=1
    buffer[0]^=keyLen

    #Step c: CBC FROG
    I=0
    stringBuffer=""
    for i in buffer:
        stringBuffer+=chr(i)
    flag=True
    randomKey=[]
    while flag:
        res=FROG_ecrypt(stringBuffer,simpleFROGinternKey)
        stringBuffer=""
        for j in res[0]:
            stringBuffer+=chr(j)
        size=2304-I
        if size>16:
            size=16
        for j in res[0]:
            randomKey.append(j)
        I+=size
        if I>=2304:
            flag=False
        randomKey=randomKey[:2304]
    return randomKey

def makePermutation(input,lastElem=15):
    use=[]
    i=0
    while i<=lastElem:
        use.append(i)
        i+=1
    last=lastElem
    index=0
    
    i=0
    while i<=lastElem-1:
        index=(index+input[i])%(last+1)
        input[i]=use[index]
        if index<last:
            use.pop(index)
        last-=1
        if index>last:
            index=0
        i+=1
    input[lastElem]=use[0]
    return input

def validate(key):
    #used=[]
    #i=0
    #while i<16:
    #    used.append(False)
    #    i+=1
    #index=0
    #i=0
    #while i<=16-2:
    #    if key[index]==0:
    #        K=index
    #        while not used[K]:
    #            K=(K+1)%16
    #        key[index]=K
    #        L=K
    #        while key[L]!=K:
    #            L=key[L]
    #        key[L]=0
    #    used[index]=True
    #    index=key[index]
    #    i+=1
    #i=0
    #while i<16:
    #    if key[i]==(i+1)%16:
    #        key[i]=(i+2)%16
    #    i+=1
    #return key
    flag=False
    cicleList=[]
    while not flag:
        tempListAnalys=[]
        l=0
        while l<16:
            tempListAnalys.append(l)
            l+=1
        while len(tempListAnalys):
            startAnalys=tempListAnalys.pop(0)
            curentAnalys=startAnalys
            tmpCicle=[]
            tmpCicle.clear()
            #if in cicle 1 element
            tmpCicle.append(key[curentAnalys])
            while startAnalys!=key[curentAnalys]:
                curentAnalys=key[curentAnalys]
                tempListAnalys.remove(curentAnalys)
                tmpCicle.append(curentAnalys)
            if(curentAnalys!=key[curentAnalys]):
                tmpCicle.append(key[curentAnalys])
            if(len(tmpCicle)!=1):
                tmpCicle.pop(0)
            cicleList.append(tmpCicle)
        flag=True
    for i in cicleList:
        tmpNumber=i[len(i)-1]
        j=cicleList.index(i)
        if j==len(cicleList)-1:
            break
        num1=tmpNumber
        num2=cicleList[j+1][len(cicleList[j+1])-1]
        index1=key.index(num1)
        index2=key.index(num2)
        key[index1]=num2
        key[index2]=num1
    i=0
    while i<16:
        if key[i]==(i+1)%16:
            key[i]=(i+2)%16
        i+=1
    return key

mK=[]
with open("key.txt") as f:
    for line in f:
        mK.append([int(num) for num in line.split()])
userKey=[]
for i in mK:
    for j in i:
        userKey.append(j)
mK.clear()
with open("startTable.txt") as f:
    for line in f:
        mK.append([int(num) for num in line.split()])
masterKey=[]
for i in mK:
    for j in i:
        masterKey.append(j)


key=hashKey(userKey,masterKey)
key2=makeInternalKey(key)
testList=[]
i=0
while i<256:
    testList.append(i)
    i+=1
for j in key2:
    print("sub key: "+str(key2.index(j)))
    i=0
    while i<256:
        if j[1].count(i)!=1:
            print(str(i)+" count "+j[1].count(i))
        i+=1

print("")

userKey2=userKey[:5]
masterKey2=masterKey[:251]
m=FROG_ecrypt("meh",key2)

n=""
for i in m:
    for j in i:
        n+=chr(j)

key3=hashKey(userKey2,masterKey2)
key4=makeInternalKey(key3)
testList.clear()
i=0
while i<256:
    testList.append(i)
    i+=1
for j in key4:
    print("sub key: "+str(key2.index(j)))
    i=0
    while i<256:
        if j[1].count(i)!=1:
            print(str(i)+" count "+j[1].count(i))
        i+=1

z=FROG_decrypt(n,key4)
l=""
for i in z:
    for j in i:
        l+=chr(j)

print("")