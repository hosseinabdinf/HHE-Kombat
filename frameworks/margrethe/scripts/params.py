from mpmath import mpf, mp, nstr
import math
mp.prec = 2000

class LeveledRGSW:
  def __init__(self, N, sigma, k, ell, bg_bit, msg_prec, verbose=False):
    self.msg_prec, self.sigma, self.N, self.k, self.ell, self.bg_bit, self.verbose = mpf(msg_prec), mpf(sigma), (N), (k), (ell), (bg_bit), verbose
    self.bg = mpf(1 << self.bg_bit)
    self.beta = self.bg/2
    self.epsilon = 1 /(2*(self.bg**self.ell))

  def vertical_packing(self, in_prec, in_var):
    term1 = (self.k + 1)*self.ell*self.N*(self.beta**2)*in_var
    term2 = (1 + self.k*self.N)*self.epsilon**2
    if(self.verbose):
      print("Vertical Packing Variance <= %d * (%12.5e + %12.5e) = 2^%f" %(in_prec, term1, term2, mp.log(in_prec*(term1 + term2), 2)))
      print("Failure Probability: 2^%s" % (self.failure_rate(in_prec*(term1 + term2))))
    return in_prec * (term1 + term2)

  def product(self, A_var, B_var):
    term1 = (self.k + 1)*self.ell*self.N*(self.beta**2)*A_var
    term2 = (1 + self.k*self.N)*self.epsilon**2
    if(self.verbose):
      print("Product Variance <= %12.5e + %12.5e + %12.5e = 2^%f" %(term1, term2, B_var, mp.log(term1 + term2 + B_var, 2)))
      print("Failure Probability: 2^%s" % (self.failure_rate(term1 + term2 + B_var)))
    return term1 + term2 + B_var
  
  def filter_Lp4(self, in_var, L=18, b=14):
    vp = self.vertical_packing(L, in_var)
    add = 4*self.product(in_var, 0)
    if(self.verbose):
      print("Filter %d+4 <= %d * (%12.5e + %12.5e) = 2^%f" %(L, b, vp, add, mp.log(b*(vp + add), 2)))
      print("Failure Probability: 2^%s" % (self.failure_rate(b*(vp + add))))
    return b*(vp + add)
  
  def failure_rate(self, var):
    interval = 2**(- self.msg_prec - 1)
    sigma = mp.sqrt(var)
    return nstr(mp.floor(mp.log(1 - mp.erf(interval/(sigma*mp.sqrt(2))), 2)))


sigma = 2**-51 #2.2148688116005568e-16
prec = 8
# mix_f = LeveledRGSW(2048, sigma, 1, 3, 12, prec, True)
# in_var = mix_f.product(sigma**2, sigma**2)

# cipher = LeveledRGSW(2048, mp.sqrt(in_var), 1, 2, 10, prec, True)

# cipher.filter_Lp4(in_var)

# print("Cipher only 2 16")
# cipher = LeveledRGSW(2048, sigma, 1, 2, 16, 12, True)
# cipher = LeveledRGSW(2048, sigma, 1, 9, 5, 32, True)
# cipher.filter_Lp4(sigma**2)

# cipher = LeveledRGSW(2048, sigma, 1, 2, 17, 20, True)
# cipher.filter_Lp4(sigma**2)

# cipher = LeveledRGSW(2048, sigma, 1, 3, 13, 28, True)
# cipher.filter_Lp4(sigma**2)

import sys
cipher = LeveledRGSW(2048, sigma, 1, 9, 5, int(sys.argv[1]), True)
# cipher.filter_Lp4(sigma**2)

print("Failure Probability: 2^%s" % (cipher.failure_rate(3*((2**-12)**2))))
print("Failure Probability: 2^%s" % (cipher.failure_rate(2*((2**-15)**2))))
print("Failure Probability: 2^%s" % (cipher.failure_rate(4*((2**-21)**2))))
print("Failure Probability: 2^%s" % (cipher.failure_rate(6*((2**-25)**2))))
print("Failure Probability: 2^%s" % (cipher.failure_rate(7*((2**-32)**2))))

# print("Cipher only 1 23")
# cipher = LeveledRGSW(2048, sigma, 1, 2, 10, 8, True)
# cipher.filter_Lp4(sigma**2)