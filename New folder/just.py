class Cipher:
	def __init__(self, key) -> None:
		self.original_key = key

	def whitening(self, word, key):
		r = []

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
			r = self.whitening(pt_hex, self.original_key)

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

if __name__ == '__main__':
	pass
	# word = "hello"
	# PT = 
	# PT_Ascii = [ord(x) for x in PT]
	
	# cipher = Cipher(key)
	# print(cipher.encrypt(word))