def deepcopy(l):
    r = list()
    for i in l:
        r.append(i)
    return r


def reverse(array, start, end):
    end -= 1
    while start < end:
        array[end] ^= array[start]
        array[start] ^= array[end]
        array[end] ^= array[start]
        start += 1
        end -= 1
    return array


def _bin(num):
    return bin(num)[2:]


def findMSB(num):
    result = 0
    while num != 0:
        num = num >> 1
        result += 1
    return result


def polynomialMutil(a, b, mod=283):  # 283 -> 0b100011011 -> x^8 + x^4 + x^3 + x + 1
    result = 0
    while b != 0:
        if b & 1:
            _, tmp = polynomialDiv(a, mod)
            result ^= tmp
        a = a << 1
        b = b >> 1
    return result


def polynomialDiv(a, b):
    '''return a / b'''
    result = 0
    remain = a
    bMSB = findMSB(b)
    rMSB = findMSB(remain)
    while rMSB >= bMSB:
        tmp = rMSB - bMSB
        result |= (1 << tmp)
        remain ^= (b << tmp)
        rMSB = findMSB(remain)
    return (result, remain)


def polynomialModInv(num, mod=283):
    if num == 0:
        return 0

    num = polynomialDiv(num, mod)[1]
    pre = [1, 0]
    curr = [0, 1]
    a = mod
    b = num
    while polynomialDiv(a, b)[1] != 0:
        tmp = deepcopy(curr)
        quotient, remain = polynomialDiv(a, b)
        curr[0] = polynomialMutil(curr[0], quotient)
        curr[1] = polynomialMutil(curr[1], quotient)
        curr[0] ^= pre[0]
        curr[1] ^= pre[1]
        a, b = b, remain
        pre = tmp

    assert b == 1, "No inv found"
    return polynomialDiv(curr[1], mod)[1]


def genSBox():
    box = [[(i * 16 + j) for j in range(16)] for i in range(16)]
    for y in range(len(box)):  
        for x in range(len(box[y])):
            num = polynomialModInv(box[y][x]) # 求 GF(2^8) 上的逆元
            num = num ^ lshift(num, 1) ^ lshift(num, 2) ^ lshift(num, 3) ^ lshift(num, 4) ^ 0b01100011 # 仿射变换
            box[y][x] = num
    return box


def genRevSBox():
    box = [[(i * 16 + j) for j in range(16)] for i in range(16)]
    for y in range(len(box)):
        for x in range(len(box[y])):
            num = box[y][x]
            num = lshift(num, 1) ^ lshift(num, 3) ^ lshift(num, 6) ^ 0b00000101
            box[y][x] = polynomialModInv(num)
    return box


def lshift(num, time):
    for _ in range(time):
        msb = num >> 7
        num = (num << 1) & (0b11111111)
        num ^= msb
    return num


def xor(a, b):
    assert len(a) == len(b)
    t = type(a)
    r = list()
    for i in range(len(a)):
        if type(a[i]) == list:
            r.append(xor(a[i], b[i]))
        else:
            r.append(a[i] ^ b[i])
    return t(r)


class AES: # AES-128-CBC
    state = [[0 for j in range(4)] for i in range(4)]  # 4 x 4, 16 * 8 = 128 bits
    sbox = genSBox()
    revsbox = genRevSBox()
    roundKey = []

    
    def printMat(self, mat):
        for y in range(len(mat)):
            for x in range(len(mat[y])):
                print(hex(mat[y][x]), end=' ')
            print('')


    def sub(self, byte):
        high = (byte & 0b11110000) >> 4
        low = byte & 0b00001111
        return self.sbox[high][low]


    def revSub(self, byte):
        high = (byte & 0b11110000) >> 4
        low = byte & 0b00001111
        return self.revsbox[high][low]


    def byteSub(self):
        for y in range(len(self.state)):
            for x in range(len(self.state[y])):
                self.state[y][x] = self.sub(self.state[y][x])

    
    def invByteSub(self):
        for y in range(len(self.state)):
            for x in range(len(self.state[y])):
                self.state[y][x] = self.revSub(self.state[y][x])


    def shiftRow(self):
        for y in range(len(self.state)):
            reverse(self.state[y], 0, y)
            reverse(self.state[y], y, len(self.state[y]))
            reverse(self.state[y], 0, len(self.state[y]))


    def invShiftRow(self):
        for y in range(len(self.state)):
            reverse(self.state[y], 0, 4 - y)
            reverse(self.state[y], 4 - y, len(self.state[y]))
            reverse(self.state[y], 0, len(self.state[y]))


    def mixColumn(self):
        tmp = [[0 for j in range(4)] for i in range(4)]
        curr = self.state
        for i in range(4):
            tmp[0][i] = polynomialMutil(curr[0][i], 2) ^ polynomialMutil(curr[1][i], 3) ^ curr[2][i] ^ curr[3][i]
            tmp[1][i] = curr[0][i] ^ polynomialMutil(curr[1][i], 2) ^ polynomialMutil(curr[2][i], 3) ^ curr[3][i]
            tmp[2][i] = curr[0][i] ^ curr[1][i] ^ polynomialMutil(curr[2][i], 2) ^ polynomialMutil(curr[3][i], 3)
            tmp[3][i] = polynomialMutil(curr[0][i], 3) ^ curr[1][i] ^ curr[2][i] ^ polynomialMutil(curr[3][i], 2)
        self.state = tmp


    def invMixColumn(self):
        tmp = [[0 for j in range(4)] for i in range(4)]
        curr = self.state
        for i in range(4):
            tmp[0][i] = polynomialMutil(curr[0][i], 14) ^ polynomialMutil(curr[1][i], 11) ^ polynomialMutil(curr[2][i], 13) ^ polynomialMutil(curr[3][i], 9)
            tmp[1][i] = polynomialMutil(curr[0][i], 9) ^ polynomialMutil(curr[1][i], 14) ^ polynomialMutil(curr[2][i], 11) ^ polynomialMutil(curr[3][i], 13)
            tmp[2][i] = polynomialMutil(curr[0][i], 13) ^ polynomialMutil(curr[1][i], 9) ^ polynomialMutil(curr[2][i], 14) ^ polynomialMutil(curr[3][i], 11)
            tmp[3][i] = polynomialMutil(curr[0][i], 11) ^ polynomialMutil(curr[1][i], 13) ^ polynomialMutil(curr[2][i], 9) ^ polynomialMutil(curr[3][i], 14)
        self.state = tmp


    def trans(self, mat):
        '''转置矩阵'''
        tmp = [[0 for j in range(len(mat[i]))] for i in range(len(mat))]
        for y in range(len(tmp)):
            for x in range(len(tmp[y])):
                tmp[y][x] = mat[x][y]
        return tmp


    def addRoundKey(self, key):
        self.state = xor(self.state, self.trans(key))


    def keyExpansion(self, seedKey):
        assert len(seedKey) == 16
        assert type(seedKey) == bytes

        tmp = [[0 for j in range(4)] for i in range(4)]
        for i in range(4):
            for j in range(4):
                tmp[i][j] = seedKey[i * 4 + j]
        seedKey = tmp

        rc = []
        i = 1
        for _ in range(10): # 生成 rc
            rc.append(i)
            i = polynomialMutil(i, 2)

        key = [[0 for j in range(4)] for i in range(4 * 11)]
        for i in range(4):
            key[i] = seedKey[i]

        for i in range(4, 4 * 11):
            tmp = deepcopy(key[i - 1])
            if i % 4 == 0:
                tmp[0], tmp[1], tmp[2], tmp[3] = tmp[1], tmp[2], tmp[3], tmp[0]
                for seq, byte in enumerate(tmp):
                    tmp[seq] = self.sub(byte)
                rcon = [rc[i // 4 - 1], 0, 0, 0]
                tmp = xor(tmp, rcon)
            key[i] = xor(key[i - 4], tmp)
        
        self.roundKey = key


    def encryptBlock(self, plaintext, seedKey):
        self.keyExpansion(seedKey)
        assert len(plaintext) == 16
        assert type(plaintext) == bytes

        tmp = [[0 for j in range(4)] for i in range(4)]
        for i in range(4):
            for j in range(4):
                tmp[j][i] = plaintext[i * 4 + j]
        self.state = tmp
        self.addRoundKey(self.roundKey[0:4])

        for i in range(1, 10):
            self.byteSub()
            self.shiftRow()
            self.mixColumn()
            self.addRoundKey(self.roundKey[i * 4:(i + 1) * 4])

        self.byteSub()
        self.shiftRow()
        self.addRoundKey(self.roundKey[-4:])

        cipher = bytearray()
        for i in range(4):
            for j in range(4):
                cipher.append(self.state[j][i])
        
        return bytes(cipher)

    
    def decryptBlock(self, cipher, seedKey):
        self.keyExpansion(seedKey)

        assert len(cipher) == 16
        assert type(cipher) == bytes

        tmp = [[0 for j in range(4)] for i in range(4)]
        for i in range(4):
            for j in range(4):
                tmp[j][i] = cipher[i * 4 + j]
        
        self.state = tmp
        self.addRoundKey(self.roundKey[-4:])

        for i in range(9, 0, -1): # 反向使用 key
            self.invByteSub()
            self.invShiftRow()
            self.addRoundKey(self.roundKey[i * 4:(i + 1) * 4])
            self.invMixColumn()
            
        self.invByteSub()
        self.invShiftRow()
        self.addRoundKey(self.roundKey[0:4])

        plaintext = bytearray()
        for i in range(4):
            for j in range(4):
                plaintext.append(self.state[j][i])
        return bytes(plaintext)


    def encrypt(self, plaintext, key, iv=b'\x00' * 16):
        if type(plaintext) != bytes:
            plaintext = plaintext.encode('utf-8')
        if type(key) != bytes:
            key = key.encode('utf-8')
        if type(iv) != bytes:
            iv = iv.encode('utf-8')
        assert len(key) == 16
        assert len(iv) == 16

        padding = 16 - len(plaintext) % 16
        plaintext += bytes([padding] * padding)
        cipher = b''
        tmpiv = iv
        for i in range(0, len(plaintext), 16):
            block = self.encryptBlock(xor(tmpiv, plaintext[i:i + 16]), key)
            cipher += block
            tmpiv = block
        return cipher
            
    
    def decrypt(self, cipher, key, iv=b'\x00' * 16):
        if type(cipher) != bytes:
            cipher = cipher.encode('utf-8')
        if type(key) != bytes:
            key = key.encode('utf-8')
        if type(iv) != bytes:
            iv = iv.encode('utf-8')
        assert len(cipher) % 16 == 0
        assert len(key) == 16
        assert len(iv) == 16

        plaintext = b''
        tmpiv = iv
        for i in range(0, len(cipher), 16):
            block = self.decryptBlock(cipher[i:i + 16], key)
            block = xor(tmpiv, block)
            plaintext += block
            tmpiv = cipher[i:i + 16]
        plaintext = plaintext[:-plaintext[-1]]
        return plaintext