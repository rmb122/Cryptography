def invert(x, m):
    def gcd(a, b):
        m = a % b
        while m != 0:
            a = b
            b = m
            m = a % b
        return b

    def solve(a, b):
        if b == 0:
            return 1, 0
        else:
            k = a // b
            m = a % b
            x1, y1 = solve(b, m)
            x, y = y1, x1 - k * y1
        return x, y

    #判断最大公约数是否为1，若不是则没有逆元
    if gcd(x, m) == 1:
        a, _ = solve(x, m)
        return a % m 
    else:
        raise Exception("No invert exists")


def random(n):
    curr = 0
    f = open('/dev/urandom', 'rb')
    while curr < n:
        curr += int.from_bytes(f.read(50), 'little')
    return curr % n


class curve():
    def __init__(self, p, a, b, G, n):
        ''''
        p 是域的模数
        a 对应 Weisestrass 方程中的 a4
        b 对应 a6
        G 是基点
        n 是 G 的阶
        '''
        self.p = p
        self.a = a
        self.b = b
        self.G = G
        self.n = n


    def add(self, pa, pb):
        '''
        pa = point a
        pb = point b
        '''
        a = self.a
        p = self.p

        if pa == pb:
            lam = ((3 * (pa[0]**2) + a) * invert(2 * pa[1], p)) % p  # 除法等于求逆元然后乘
        else:
            lam = ((pb[1] - pa[1]) * invert(pb[0] - pa[0], p)) % p

        x = lam ** 2 - pa[0] - pb[0]
        y = lam * (pa[0] - x) - pa[1]
        x = x % p
        y = y % p
        return (x, y)


    def mul(self, point, mulnum):
        tmp = point
        result = None

        while mulnum != 0: # 采用重复倍加算法
            if (mulnum & 1) == 1:
                if result is None:
                    result = tmp
                else:
                    result = self.add(tmp, result)

            tmp = self.add(tmp, tmp)
            mulnum = mulnum >> 1
        return result


    def minus(self, pa, pb):
        pb = (pb[0], -pb[1])
        result = self.add(pa, pb)
        return result


class secp256k1(curve):
    '''
    详见 http://www.secg.org/sec2-v2.pdf, 这里采用 secp256k1 这条曲线
    '''
    def __init__(self):
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
        a = 0x0
        b = 0x7
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        super(secp256k1, self).__init__(p, a, b, G, n)


class publicKey():
    def __init__(self, p):
        self.c = secp256k1() # 椭圆曲线
        self.p = p
        self.mapTable = []
        for i in range(0, 256): # 生成映射表
            self.mapTable.append(c.mul(c.G, i))
    

    def encode(self, msg):
        result = []
        msg = msg.encode()
        for i in msg:
            result.append(self.mapTable[i])
        return result


    def encryptPoint(self, point):  # 多个点公用一个 k 会降低安全性
        k = random(c.n)
        cipher = c.add(point, c.mul(self.p, k))
        return (c.mul(c.G, k), cipher)

    
    def encryptMsg(self, msg):
        msg = self.encode(msg)
        cipher = []
        for p in msg:
            cipher.append(self.encryptPoint(p))
        return cipher


class privateKey():
    def __init__(self, n):
        self.c = secp256k1() # 椭圆曲线
        self.n = n
        self.mapTable = dict()
        for i in range(0, 256): # 生成映射表
            self.mapTable[c.mul(c.G, i)] = i
    

    def decode(self, points):
        result = [] 
        for i in points:
            result.append(self.mapTable[i])
        result = bytearray(result)
        result = result.decode()
        return result

    
    def decryptPoint(self, pointPair):
        m = c.minus(pointPair[1], c.mul(pointPair[0], self.n))
        return m
    

    def decryptMsg(self, pointPairs):
        points = []
        for i in pointPairs:
            p = self.decryptPoint(i)
            points.append(p)
        return self.decode(points)
 

def getKeyPair():
    c = secp256k1()
    n = random(c.n)  # 私钥
    p = c.mul(c.G, n) # 用私钥生成公钥
    return (privateKey(n), publicKey(p))


class ECDH():
    def __init__(self):
        self.c = secp256k1() # 椭圆曲线
        self.k = random(c.n)
        self.p = c.mul(c.G, self.k)
    
    def sendPublic(self):
        return self.p
    
    def getCommonKey(self, p):
        return c.mul(p, self.k)


c = secp256k1()
pri, pub = getKeyPair()
msg = pub.encryptMsg("test")
print(msg)
print(pri.decryptMsg(msg))

print("\nECDH")
a = ECDH()
pa = a.sendPublic()
b = ECDH()
pb = b.sendPublic()

print(a.getCommonKey(pb))
print(b.getCommonKey(pa))