'''
Reused Nonce Attack on ECDSA
Challenge Title: Signed Jeopardy
'''

from sage.all import * # For elliptic curves
from hashlib import sha512 # For hasing the message (we actually sign the HASH of the message, not the message itself)
from ecdsa.numbertheory import inverse_mod # inverse_mod == division (when moduli are involved)

# P521 standard curve parameters (from 'server.sage')
p = 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151
a = 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057148
b = 1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984
Gx = 2661740802050217063228768716723360960729859168756973147706671368418802944996427808491545080627771902352094241225065558662157113545570916814161637315895999846
Gy = 3757180025770020463545507224491183603594455134769762486694567779615544477440556316691234405012945539562144444537289428522585666729196580810124344277578376784
E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy) 
n = 6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449

# Note: n == the order of G (G == elliptic curve base point) which represents the total
# number of different possible points over the curve 

# Question 1: Rare was bought by this company for $3.19 billion.
m1 = "What is " + "Microsoft".upper() + "?"

# Question 2: Category of Pokemon that contain some Pokemon like Victini, Mew, Magearna and Zarude.
m2 = "What is " + "Mythical".upper() + "?"

# Compute the SHA512 hashes of the answers
z1 = int(sha512(m1.encode()).hexdigest(), 16)
z2 = int(sha512(m2.encode()).hexdigest(), 16)

# Signature (r1, s1) of the first answer
r1 = 1465592089909096066855017733143775914413407269725815519508066282537319512650079216133639660455072377153032233958108330075714003734901092347020299988719621322
s1 = 545531076356108942170542517291585227912890321475211086646343990428230857512990453752368923962766593723868745103465428375270149723925686204794806188631057460

# Signature (r2, s2) of the second answer
r2 = 1465592089909096066855017733143775914413407269725815519508066282537319512650079216133639660455072377153032233958108330075714003734901092347020299988719621322
s2 = 4189612857039624039238953485069358484257973951950638665234391677969348904883268302761678805371275339935843305522229259291269025045916960785357191121407045404

# r must be equal for this to work (this is assumed, but we check just in case)
assert(r1 == r2)

# In the Elliptic Curve Digital Signature Algorithm, if the same k is used to sign
# different signatures (which is the case here), the attacker can recover k using
# the signatures (see https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm):
m_diff = (z1 - z2) % n
r1_inv = inverse_mod(r1, n)
s_diff = (s1-s2) % n

# Recover k and d using the formulas from the Wikipedia page
# Note that division is actually multiplication by the modular inverse!!
k = (m_diff * inverse_mod(s_diff, n)) % n
d = (((((s1 * k) % n) - z1) % n) * r1_inv) % n

# Now, sign a dummy message with the calculated keys and print out the signature
m_dummy = "hello"
m_dummy_hash = int(sha512(m_dummy.encode()).hexdigest(), 16)
P = k*G
r = int(P[0]) % n
k_inv = inverse_mod(k, n)
s = (((m_dummy_hash + ((r*d)%n)) % n) * k_inv) % n

# Print the recovered values (k & d) and the forged signature (r, s) to the console
print(f'k = {k}')
print(f'd = {d}')
print(f'r = {r}')
print(f's = {s}\n')
