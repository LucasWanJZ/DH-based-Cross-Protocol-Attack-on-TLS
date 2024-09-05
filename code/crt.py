from cypari2 import Pari

def mod_inverse(a, b):
    """Compute the modular inverse of a under modulo b."""
    original_b = b
    x0, x1 = 0, 1
    while a > 1:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1 - q * x0, x0
    
    if x1 < 0:
        x1 += original_b
    
    return x1

# Initialize Pari
pari = Pari()

# Constants
Primes = [518177537, 518177551, 518177593, 518177599, 518177609, 518177641, 518177651, 518177689, 518177717, 518177729, 518177749, 518177761, 518177813, 518177857, 518177903, 518177917, 518177923, 518177929, 518177987, 518177999, 518178019, 518178041, 518178053, 518178091, 518178107, 518178169, 518178181, 518178211, 518178217, 518178233, 518178257, 518178263, 518178281, 518178307, 518178313, 518178319, 518178341, 518178373, 518178407, 518178421, 518178433, 518178439, 518178443, 518178449, 518178457, 518178481, 518178497, 518178511, 518178571, 518178587, 518178593, 518178611, 518178629, 518178667, 518178709, 518178761, 518178779, 518178809, 518178833, 518178839, 518178841, 518178883, 518178953, 518178959, 518178961, 518178967, 518178977, 518178979, 518179003, 518179027, 518179037, 518179061, 518179097, 518179099, 518179127, 518179199, 518179219, 518179231, 518179243, 518179303, 518179309, 518179349, 518179373, 518179391]

public = int("CB5BF0EC20AA337A6B8C3E0E00A6FD05566BDDCAFFAD1DEE44893A0156A9AA54B6E3EC8F5FDA40940137DDD93E2705F1C960346FC126BD3634B5015AD1FA71CABA73D6EDFCE2F8AA5CA96E9D99BEC0A2662B33FFCD9068C81916DB27CF2A6DFED0A33D3E54BE6CBECB91FCE790FA8F5EF14FCD2EE768DDD8C3BB3154BA457A08A78E3FC4C7D484AB65753E1226D4A0128E403339C457444BD1B8814586CC49C6702289061DA6C626D5C3E3AC8553F87C91F8331480FAEC16904FEF26CC966FB799D196BC9EF38BF897FA43011642C26BDB621BFF797810F01D4F98D41BBFCB60828844A478C7AAD292216367C2C1CCB7890D83AC44F3DC287A0443047245E60B2F9A4F5593E0D82B8279EEEB9F6931039E97A86C83B34D3D6A10FA16D49AD432F9E6093F44FDB5255E080C3C54064E80", 16)
private = int("6D5A521E321A26F6F643607CE65FCA50008C0CBF6642E79E1C5880D3A1503B664F51FA278A4E3842E6A7301147CE77F704860198A2B03ACB00FF0DB28B3F408465BF2B5CD3716B8F0357FE1F499C77AB1A46617203F24228EDFFA42E25EA82998F22D04D379F3AFBF3E2B4F2F7B5F74C7BB909EB7A4F4E5FE9410DB4B669E8DB8F1DE58CCF987BC523F4CA37105C847D3376457D4F6458C08C56CBDA28B76570C5E734CDF04EA1EE2538E6F77D0431EDA58F45E83838A110AB83CC765A626625574127F917AA8EBE4B54B7CFB24D6E2E07EEF428D785C0BBF9BE55E992085365233B69CA1FFDA9D01E19FFA5D2F0DB2510431A265D4874CE1DC440D9C265ABD342F34D003016808FB98F6809A61B287DF1634FDF8AC2145FB6925CCB057EA4AFB071F39D2285A8E5503E31459D2A0B54", 16)
base = int("1f9609b6473a4fb0a14627856351e1038ad367459a4c406f421ab94ea597ce812046264b9371451dce6969d40b45e7bf4ca3f9757ddf6e4069e616cd2721e40b63958e722e85788ed1d65ff0450b0ba3c31214555877", 16)

# Lists to store results
res = []
m = []
N = []

# Compute the product of all primes
n = 1
for p in Primes:
    n *= p

# Compute results using Chinese Remainder Theorem
for p in Primes:
    y = pari.Mod(public, p)
    res_i = pari.znlog(y, pari.Mod(base, p))
    res.append(int(res_i))
    m_i = n // p
    m.append(m_i)
    N_i = mod_inverse(m_i, p)
    N.append(N_i)

# Compute x using the CRT
x = 0
for i in range(len(Primes)):
    x += res[i] * m[i] * N[i]

x = x % n

print("n =", n)
print("x =", x)
print("base =", base)
print("public =", public)
print("private =", private)

# Check if x equals private key
if x == private:
    print("Success! The computed x matches the private key.")
else:
    print("Mismatch! The computed x does not match the private key.")
