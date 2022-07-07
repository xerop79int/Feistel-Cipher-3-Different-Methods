import key_generator as KG

class Cipher:
    def __init__(self, key):
        self.original_key = key
        self.keys = KG.KeyGenerator.generateKeys()
    def whitening(self, word):
            r = []

            key = int(self.original_key, 16)
            key = format(key, "016x")
            for i in range(0, 4):
                j = i * 4

                sw = word[j: j + 4]
                sk = key[4 * i:4 * i + 4]
                w = int(sw, 16) ^ int(sk, 16)
                r.append(w)
            return r

    def g_function(self, r, k0, k1, k2, k3):
        r = format(r, '04x')
        g1 = int(r[:2], 16)
        g2 = int(r[2:4], 16)
        g3 = int(self.ftable[g2 ^ k0]) ^ g1
        g4 = int(self.ftable[g3 ^ k1]) ^ g2
        g5 = int(self.ftable[g4 ^ k2]) ^ g3
        g6 = int(self.ftable[g5 ^ k3]) ^ g4
        return int(format(g5, '02x') + format(g6, '02x'), 16)

    def f_function(self, r0, r1, round):
        k = self.keys[round]

        t0 = self.g_function(r0, k[0], k[1], k[2], k[3])
        t1 = self.g_function(r1, k[4], k[5], k[6], k[7])

        k89 = int(format(k[8], '02x') + format(k[9], '02x'), 16)
        kab = int(format(k[10], '02x') + format(k[11], '02x'), 16)
        f0 = (t0 + 2 * t1 + k89) % self.const_2_16
        f1 = (2 * t0 + t1 + kab) % self.const_2_16
        return [f0, f1]

    def round_function(self, r, round):
        f = self.f_function(r[0], r[1], round)

        new_r0 = r[2] ^ f[0]
        new_r1 = r[3] ^ f[1]
        new_r2 = r[0]
        new_r3 = r[1]
        return [new_r0, new_r1, new_r2, new_r3]

    def encrypt(self, pt_hex):
            r = self.whitening(pt_hex)

            for i in range(0, 16):
                r = self.round_function(r, i)

            y = [r[2], r[3], r[0], r[1]]
            y_hex = ""
            for yi in y:
                y_hex += format(yi, "04x")

            c = self.whitening(y_hex, self.original_key)
            c_str = ""
            for ci in c:
                c_str += format(ci, "04x")
            return c_str

class File_handling:
    def getSrcFromFile(self, src_file, mode):
        try:
            file = open(src_file, 'r')
        except IOError:
            print("Error: Can't open the \"" + src_file + "\" file.")
        with file:
            hex_strings = []
            counter = 0
            i = -1
            while True:
                c = file.read(1)
                if not c:
                    break
                if counter % 16 == 0:
                    hex_strings.append("")
                    i += 1
                if mode == "-e":
                    c = format(ord(c), "02x")
                    counter += 1
                counter += 1
                hex_strings[i] += c

            if i < 0:
                raise ValueError("Error: the source file is empty!")
            hex_strings[i] = format(int(hex_strings[i], 16), "016x")
            return hex_strings

                
if __name__ == '__main__':
    original_key = '\xe8r\x15\xe1\x87\xbb\x0c\\\x1a\x0e\xfd#\x98\x83".\x08\xd4\x84\xe4N{\x1d\xe28l\xac\xe94o\x913'
    key = ""
    for x in original_key:
                key += format(ord(x), "02x")
    cipher = Cipher(key)

    mode = "-e"
    file_handling = File_handling()
    src = file_handling.getSrcFromFile("hello.txt", mode)
    results = []

    for s in src:
        if mode == "-e":
            results.append(cipher.encrypt(s))
        else:
            results.append(cipher.decrypt(s))

    print(results)
    
