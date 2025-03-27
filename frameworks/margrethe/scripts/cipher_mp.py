import random, hashlib

bit_invert = lambda x: int(bin(x)[2::][::-1],2)

class Random:
  def __init__(self, seed=None):
    self.seed = seed if seed else random.SystemRandom().randint(0, 2**256).to_bytes(256//8, 'little')
    self.hash = hashlib.shake_256()
    self.hash.update(self.seed)
    self.idx = 0
    self.rnd_stream_size = 100000
    self.buffer = self.hash.digest(self.rnd_stream_size)
    print(list(self.buffer[:20]))

  def rand_int(self, a, b):
    rnd = int.from_bytes(self.buffer[self.idx:self.idx+4], "little")
    self.idx += 4
    rnd *= (b - a)
    rnd //= 2**32
    # print(a + rnd)
    return a + rnd
  
  def reset(self):
    self.idx = 0


class Cipher:
  def __init__(self, key=None, rnd=None, lut=None, lut_size=20, add_size=4, num_rounds=14, output_size=16):
    self.lut_size, self.add_size, self.num_rounds, self.output_size = lut_size, add_size, num_rounds, output_size
    self.key = key if key else self.keygen()
    self.rnd = rnd if rnd else Random()
    self.lut = lut if lut else self.gen_lut()
    self.s = self.key.copy()

  def save(self, file=None):
    txt = """
const uint8_t _test_data_rnd[%d] = {%s};
const uint8_t _test_data_server_key[%d] = {%s};
const uint8_t _test_data_client_key[%d] = {%s};
uint64_t _test_data_lut[%d] = {%s};
const uint16_t _test_data_result[%d] = {%s};
    """ % (
      256//8,
      str(list(self.rnd.seed))[1:-1],
      len(self.key_server),
      str(self.key_server)[1:-1],
      len(self.key_client),
      str(self.key_client)[1:-1],
      2**self.lut_size,
      str(list(map(hex, self.lut)))[1:-1].replace("'", ""),
      32,
      str(self.stream(32))[1:-1]
    )
    if(file): 
      fd = open(file, "w+")
      fd.write(txt)
      fd.close()
    else: print(txt)

  def keygen(self):
    sr = random.SystemRandom()
    self.key_server = [sr.randint(0,1) for _ in range(2048)]
    self.key_client = [sr.randint(0,1) for _ in range(2048)]
    return [i ^ j for i,j in zip(self.key_server, self.key_client)]
  
  def gen_lut(self):
    sr = random.SystemRandom()
    return [sr.randint(0,2**self.output_size - 1) for _ in range(2**self.lut_size)]

  def stream(self, output_size=1):
    self.s = self.key.copy()
    self.rnd.reset()
    res = []
    for _ in range(output_size):
      x = self.sample_x12()
      x = self.whitening(x)
      res.append(self.filter(x))
    return res

  def filter(self, x):
    lut_mask = 2**self.lut_size - 1
    eval_filter = lambda i: self.lut[i&lut_mask] + (i >> self.lut_size)
    return sum(map(eval_filter, x))%(2**self.output_size)

  def whitening(self, x, size=None):
    if not size: size = (self.lut_size + self.add_size)
    return [i ^ self.rnd.rand_int(0, 2**size) for i in x]

  def sample_x12(self, count=None):
    if not count: count = (self.lut_size + self.add_size)
    for i in range(self.num_rounds*count):
      r = self.rnd.rand_int(i, 2048)
      self.s[r], self.s[i] = self.s[i], self.s[r]
    res = []
    for i in range(self.num_rounds):
      res.append(int("".join(map(str, self.s[i*count:(i+1)*count]))[::-1], 2))
    return res

c = Cipher(lut_size=18, output_size=4)
print(c.stream(32))
c.save("include/test_data_mp.h")