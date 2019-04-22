class SHA1():
    msg = bytearray()
    ra = 0x67452301
    rb = 0xefcdab89
    rc = 0x98badcfe
    rd = 0x10325476
    re = 0xc3d2e1f0

    def __init__(self, msg):
        if type(msg) == str:
            msg = msg.encode()
        self.msg = bytearray(msg)

    
    def __padding(self):
        length = len(self.msg)
        pad = length % 64
        if pad >= 56:
            pad = (64 + 56) - pad
        else:
            pad = 56 - pad
        if pad > 0:
            self.msg.extend([0x80] + [0] * (pad - 1))

        length *= 8
        length = length % 0x10000000000000000
        for _ in range(8):
            b = (length & 0xff00000000000000) >> 56
            length = length << 8
            self.msg.append(b)
    

    def __xor(self, a, b):
        t = type(a)
        r = []
        assert len(a) == len(b)
        for i in range(len(a)):
            r.append(a[i] ^ b[i])
        return t(r)


    def __getCurrCv(self):
        return [self.ra, self.rb, self.rc, self.rd, self.re]


    def __byte2num(self, byte):
        r = 0
        for i in byte:
            r = r << 8
            r ^= i
        return r

    
    def __not(self, num):
        r = 0
        for _ in range(32):
            r = r << 1
            high = (num & 0x80000000) >> 31
            r ^= 1
            r ^= high
            num = num << 1
            num &= 0xffffffff
        return r


    def __cls(self, num, time):
        for _ in range(time):
            h = (num & 0x80000000) >> 31
            num = num << 1
            num ^= h
            num &= 0xffffffff
        return num


    def __groupLoop(self):
        lastCv = self.__getCurrCv()
        words = []
        for i in range(0, 64, 4):
            words.append(self.__byte2num(self.msg[i:i + 4]))

        for i in range(16, 80):
            tmp = words[i - 16] ^ words[i - 14]
            tmp = tmp ^ words[i - 8]
            tmp = tmp ^ words[i - 3]
            tmp = self.__cls(tmp, 1)
            words.append(tmp)

        for i in range(20):
            func = lambda x,y,z: (x & y) | (self.__not(x) & z)
            self.__round(func, 0x5a827999, words[i])
        
        for i in range(20, 40):
            func = lambda x,y,z: x ^ y ^ z
            self.__round(func, 0x6ed9eba1, words[i])

        for i in range(40, 60):
            func = lambda x,y,z: (x & y) | (x & z) | (y & z)
            self.__round(func, 0x8f1bbcdc, words[i])

        for i in range(60, 80):
            func = lambda x,y,z: x ^ y ^ z
            self.__round(func, 0xca62c1d6, words[i])

        self.ra = (self.ra + lastCv[0]) % 0x100000000
        self.rb = (self.rb + lastCv[1]) % 0x100000000
        self.rc = (self.rc + lastCv[2]) % 0x100000000
        self.rd = (self.rd + lastCv[3]) % 0x100000000
        self.re = (self.re + lastCv[4]) % 0x100000000


    def __round(self, func, constant, word):
        tmpRa = func(self.rb, self.rc, self.rd)
        tmpRa += self.re
        tmpRa += self.__cls(self.ra, 5)
        tmpRa += word
        tmpRa += constant
        tmpRb = self.ra
        tmpRc = self.__cls(self.rb, 30)
        tmpRd = self.rc
        tmpRe = self.rd
        self.ra = tmpRa % 0x100000000
        self.rb = tmpRb % 0x100000000
        self.rc = tmpRc % 0x100000000
        self.rd = tmpRd % 0x100000000
        self.re = tmpRe % 0x100000000
            

    def __hex(self, num):
        return hex(num)[2:].rjust(40, '0')


    def digest(self):
        digest = bytearray.fromhex(self.hexdigest())
        return digest
    

    def hexdigest(self):
        self.__padding()
        while len(self.msg) >= 64:
            self.__groupLoop()
            self.msg = self.msg[64:]
        digest = 0
        digest += self.ra
        digest = digest << 32
        digest += self.rb
        digest = digest << 32
        digest += self.rc
        digest = digest << 32
        digest += self.rd
        digest = digest << 32
        digest += self.re
        return self.__hex(digest)