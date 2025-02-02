---
layout: post
title:  "Write-up for AlpacaHack Round 9 (Crypto)"
tags: [CTF, AlpacaHack, Crypto, CyKor, ah_p_uh]
date:   2025-02-01
---
**Written by [Minsun Kim](https://x.com/ah_p_uh)**
<br>
<br>
Hello, I am Minsun Kim, also known as `soon-haari` and I participated [AlpacaHack CTF Round 9](https://alpacahack.com/ctfs/round-9/scoreboard) which was held in **1/26**.<br>
Blog: [https://soon.haari.me/](https://soon.haari.me/)<br>

[AlpacaHack](https://x.com/AlpacaHack) is a CTF/wargame platform organized by various japanese CTF players. It holds individual CTFs every couple weeks. However unlike [Dreamhack](https://x.com/dreamhack_io)'s weekly CTF, every CTF focuses on a single category which is one of **Pwn, Rev, Web, Crypto**. Both ways should have pros and cons of course, but if you are currently a player focused on one skillbase like Zenitsu and Megumin, more than a all-arounder, you may be interested in participating AlpacaHack CTF.

![](./assets/2025-02-01-Write-Up-AlpacaHack-scoreboard.png)

4 challenges were released, and players were given 6 hours to solve it. The difficulty varies from easy challenges to hard ones, so beginners can participate for educational purposes as well. [Chocorusk](https://x.com/nuo_chocorusk) and [maple3142](https://x.com/maple3142) presented the awesome crypto challenges this round, and I will review all 4 challenges. Not only the solution, I will also share the steps I went through, or some struggles.

Please check out [Chocorusk's write-up](https://chocorusk.hatenablog.com/entry/2025/01/26/180123) and [maple3142's write-up](https://github.com/maple3142/My-CTF-Challenges/tree/master/AlpacaHack%20Round%209/ffmac) as well!

## RSAMPC (11 solves)
> I calculated the RSA public key using multi-party computation.  
Author: Chocorusk

**chall.py**
```python
import os
from Crypto.Util.number import getRandomRange, getPrime, bytes_to_long

FLAG = os.environ.get("FLAG", "fakeflag").encode()

def additive_share(a):
    t0, t1 = getRandomRange(-2**512, 2**512), getRandomRange(-2**512, 2**512)
    t2 = a-t0-t1
    return t0, t1, t2

def replicated_share(a):
    t = additive_share(a)
    return [(t[i], t[(i+1)%3]) for i in range(3)]

def multiply_shares(sa, sb):
    def mul(t, u):
        return t[0]*u[0]+t[0]*u[1]+t[1]*u[0]
    r = additive_share(0)
    z = [mul(sa[i], sb[i])+r[i] for i in range(3)]
    w = [(z[i], z[(i+1)%3]) for i in range(3)]
    return w

def reconstruct(s):
    return s[0][0] + s[0][1] + s[1][1]

p = getPrime(512)
q = getPrime(512)

sp = replicated_share(p)
sq = replicated_share(q)
print("your share of p:", sp[0])
print("your share of q:", sq[0])

spq = multiply_shares(sp, sq)
print("your share of pq:", spq[0])

n = reconstruct(spq)
assert n == p*q
print("n:", n)

e = 0x10001
c = pow(bytes_to_long(FLAG + os.urandom(127-len(FLAG))), e, n)
print("e:", e)
print("c:", c)
```

A sharing system is implemented, where sum of 3 values are equal to the secret, and 2 values are shared. Function `multiply_shares` implements multiplying two shares, and we can see it is working fine by `assert n == p*q`.

It is easy to notice `additive_share` function's random generation size is fixed to 512 bits, which is suspicious. It would be safe for `sp, sq` since `p, q` are 512 bits, however it shouldn't be for reconstructing `n`.

We first arrange what problem we are dealing with by some equations.
$$
p = t_1 + t_2 + t_3
$$
$$
q = u_1 + u_2 + u_3
$$
`t_1, t_2, u_1, u_2` is shared with the user. Let's represent `spq` with those values as well. Note that `w[0], w[1]` is only shared, which are equal to `z[1], z[2]`.
$$
z_1 = \textnormal{mul}(\textnormal{sp[1], sq[1]}) + r_1 = (t_1u_1 + t_2u_1 + t_1u_2) + r_1
$$
$$
z_2 = \textnormal{mul}(\textnormal{sp[2], sq[2]}) + r_2 = (t_2u_2 + t_3u_2 + t_2u_3) + r_2
$$
By the first equation, we can recover $r_1$, however not so helpful. The next strategy is to assign $t_3 = p - t_1 - t_2, u_3 = q - u_1 - u_2$ to remove unknowns, and we may be able to use the fact $pq = n$ where we know the valae of $n$.

$$
z_2 = (t_2u_2 + (p - t_1 - t_2)u_2 + t_2(q - u_1 - u_2)) + r_2
$$
$$
pu_2 + qt_2 = z_2 + (t_1u_2 + t_2u_1 + t_2u_2) - r_2
$$
Since $p, u_2, q, t_2$ are all the values of bitsize 512, so the value should be around 1024 bitsize. However unknown $r_2$ of 512 bit exists, so we can know the 512 most significant bits of $pu_2 + qt_2$. We also know the product of the two terms: $pu_2 * qt_2 = nu_2t_2$.

We can apply the quadratic formula, because the sum's error is only around $\frac{1}{2^{512}}$, so we can still recover result of $pu_2, qt_2$ with quite a lot of precision, specifically similarly to 512 bits. After dividing the result by $u_2, t_2$ respectively, we can recover $p, q$ value which is theoretically out by only a few bits, and finally finish the factorization.

**ex.sage**
```python
sp = (..., ...)
sq = (..., ...)
spq = (..., ...)
n = ...
e = 65537
c = ...

t1, t2 = sp
u1, u2 = sq

z = spq[1]
z += u2 * t2 + u1 * t2 + u2 * t1

mul = n * u2 * t2

p = ((z^2 - 4 * mul).sqrt() + z) / (2 * u2)
p = round(p)

for i in range(-500, 500):
	if n % (p + i) == 0:
		p = p + i
		break
else:
	print("fail")

q = n // p
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, n)

from Crypto.Util.number import *

print(long_to_bytes(m))
```

I heard there was someone who solved it by directly pushing the value to z3-solver. Since the relations are quite simple, I assumed it should be doable as well.

## addprimes (13 solves)
> addprimes in PARI/GP is useful for implementing RSA decryption.  
Author: Chocorusk

**server.sage**
```python
import os
import signal
from sage.misc.banner import require_version
from Crypto.Util.number import getPrime, bytes_to_long

assert require_version(10), "This challenge requires SageMath version 10 or above"

signal.alarm(30)
FLAG = os.environ.get("FLAG", "Alpaca{*** FAKEFLAG ***}").encode()
assert FLAG.startswith(b"Alpaca{")

p = getPrime(512)
q = getPrime(512)
n = p * q
e = 37

print("n:", n)
print("e:", e)

c = int(input("ciphertext: "))
assert 1 < c < n-1
pari.addprimes(p)
m = mod(c, n).nth_root(e)
print("plaintext:", m)

padded_flag = FLAG + os.urandom(127-len(FLAG))
print("encrypted flag:", pow(bytes_to_long(padded_flag), e, n))
```

The challenge uses SageMath server for an RSA challenge, which implies that the challenge will use some unusual functions. Also, we can notice public exponent `e` is unusually small.

We can immediately think of the case where `e` not being coprime to the ring's multiplicative order `(p - 1) * (q - 1)`. Let's think what will be printed when that happens.

Generally, function `nth_root` is not supposed to be calculated on unfactored composite modulo rings, especially like this case when `n` is big, however by calling `pari.addprimes(p)`, the internal factorization is finished, and it can be assumed the result would be CRT of `nth_root` results on prime moduli.

If $e \nmid p - 1$, we know the result of `nth_root` is unique, and SageMath knows that too. However, SageMath also knows that the result of `nth_root` is not unique when $e \mid p - 1$.

Which is why `all` parameter exists in SageMath's `nth_root`.
```python
sage: p = 0x10001
sage: Fp = GF(p)
sage: c = Fp(13131)^4
sage: c.nth_root(4)
19149
sage: c.nth_root(4, all=True)
[19149, 13131, 46388, 52406]
```
We can notice that the result is not unique, and there's a big chance where the root is not equal to the plaintext that we intended.

So by sending $m^e$ to the server, the server will reply $m$ in cases where $e \nmid p - 1$ and $e \nmid q - 1$, however if $e \mid p - 1$, $e \nmid q - 1$, the `nth_root` result should be same with $m$ over modulo $p$ but high chance it's not for $q$.

Thus, by calculating $\textnormal{GCD}(n, m - \textnormal{server\_m})$ would spit out one of the factors in around $\frac{2}{e}$ chance.

Brute-forcing the following code a bit would easily recover the factors. Then we can decrypt the encrypted flag.

**ex1.sage**
```python
from pwn import *

a = randrange(2^1000)

while True:
	# io = process(["sage", "server.sage"])
	io = remote("34.170.146.252", 20209r)

	io.recvuntil(b"n: ")
	n = ZZ(int(io.recvline()))

	io.sendline(str(pow(a, 37, n)).encode())

	io.recvuntil(b"plaintext: ")
	pt = ZZ(int(io.recvline()))
	io.recvuntil(b"flag: ")
	enc = ZZ(int(io.recvline()))

	io.close()

	if pt == a:
		continue
	break

p = gcd(a - pt, n)
q = n // p

print(f"{p, q, enc =}")
```

## Equivalent Privacy Wired (2 solves)
> I heard that WEP is vulnerable, so I modified it a bit.  
Author: Chocorusk

**server.py**
```python
import os
import signal
from Crypto.Cipher import ARC4
import string
import random

signal.alarm(300)
FLAG = os.environ.get("FLAG", "Alpaca{*** FAKEFLAG ***}")

chars = string.digits + string.ascii_lowercase + string.ascii_uppercase
master_key = "".join(random.choice(chars) for _ in range(16)).encode()

for _ in range(1000):
    iv = bytes.fromhex(input("iv: "))
    ciphertext = bytes.fromhex(input("ciphertext: "))
    key = master_key + iv
    plaintext = ARC4.new(key, drop=3072).decrypt(ciphertext)
    if plaintext == master_key:
        print(FLAG)
        break
    print("plaintext:", plaintext.hex())
```

With the limited query of 1000, we have to recover the key when we can set the key to `key + iv`. 
> If you played [CryptoHack](https://cryptohack.org/) before, and tried the challenge **Oh SNAP** in **Symmetric Ciphers** category, this shouldn't have been too much of a hard challenge.  
However, I forgot everything about it during the CTF, and went through RC4's wikipedia docs.

[RC4 - Key-scheduling algorithm (KSA)](https://en.wikipedia.org/wiki/RC4#Key-scheduling_algorithm_(KSA)) has a simple implementation of how key is used to permute `S`. It can easily be noticed that the key is repeated unlimited times until 256 iteration is done, which can create lot's of colliding keys.

Assume the key is `"1337deadbeef"` in hex, Then if we set iv to null bytes of length 249, the 256 key stream will be the following:
```
00 01 02 03 04 ... fa fb fc fc fe ff
13 37 de ad be ... 00 00 00 00 00 ??
```
But padded to:
```
00 01 02 03 04 ... fa fb fc fc fe ff
13 37 de ad be ... 00 00 00 00 00 13
```

The result should be equal when we set iv to `bytes([0x00] * 249 + [0x13])`, so that the steram their key generating are the same. We can brute force the possible bytes, which has possibilities within `chars = string.digits + string.ascii_lowercase + string.ascii_uppercase`, so possibilities of 62. Note that this is significantly less than 256, the number of all possible bytes.

So max `(62 + 1) * 16 = 1008` queries are needed, in average `(31 + 1) * 16 = 512`.

Hoever, I was in bit of a rush to wait 512 interactive connections :pepega:, so I discarded the last character and made it `(61 + 1) * 16 = 992` queries. The probability is still $\left( \frac{61}{62} \right)^{16} \simeq 0.77$ which is not so bad.

**ex.py**
```python
from pwn import process, remote, xor
import string
from tqdm import trange
from Crypto.Cipher import ARC4

chars = string.digits + string.ascii_lowercase + string.ascii_uppercase
assert len(chars) == 62
chars = chars[:61]

l = len(chars)

io = remote("34.170.146.252", 38920)
# io = process(["python3", "server.py"])

key = b""

for pos in trange(16):
	assert len(key) == pos

	pfx = bytes(255 - pos - 16)
	io.sendline(pfx.hex().encode())
	io.sendline(bytes(32).hex().encode())

	for i in range(l):
		to_send = pfx + key + chars[i].encode()
		io.sendline(to_send.hex().encode())
		io.sendline(bytes(32).hex().encode())

	pts = []
	for i in range(l + 1):
		io.recvuntil(b"plaintext: ")
		pt = bytes.fromhex(io.recvline().decode())
		pts.append(pt)

	real, pts = pts[0], pts[1:]
	by = pts.index(real)

	if by == -1:
		print("fail")
		exit()
	key += chars[by].encode()

ct = ARC4.new(key, drop=3072).decrypt(bytes(16))
ct = xor(key, ct)
io.sendline(b"")
io.sendline(ct.hex().encode())

io.interactive()
```

## ffmac (2 solves)
> just a simple message authentication code based on finite fields.  
Author: maple3142

**server.sage**
```python
import os
import signal
from Crypto.Cipher import AES

signal.alarm(300)
FLAG = os.environ.get("FLAG", "Alpaca{*** FAKEFLAG ***}")

p = 2**127 - 1
k = 16
F = GF((p, k), "x")

def keygen():
    return [F.random_element() for _ in range(6)]


def to_list(el):
    return el.polynomial().padded_list(k)


def to_element(lst):
    return F(list(lst))


def ffmac(key, x):
    k1, k2, k3, k4, k5, k6 = key
    l, r = k1, x
    for i in range(127):
        if i % 2:
            r = r * l * k2
            l = l * l
        else:
            l = l * r * k3
            r = r * r
        l, r = r, l
    return k4 * l + k5 * r * x + k6


def encrypt(key, pt):
    cipher = AES.new(key, AES.MODE_CTR)
    return cipher.nonce + cipher.encrypt(pt)


mackey = keygen()
challenge = os.urandom(k)
print("Can you help to analyze the security of my new MAC scheme?")
while True:
    print("1. Compute MAC")
    print("2. Get flag")
    option = int(input("> "))
    if option == 1:
        inp = input("input: ").encode()
        if len(inp) != k or inp == challenge:
            print("invalid input")
            exit(1)
        mac_input = ffmac(mackey, to_element(inp))
        print(f"mac(input): {to_list(mac_input)}")
    elif option == 2:
        print(f"challenge: {challenge.hex()}")
        mac_list = [int(x) for x in input("mac: ").split(",")]
        if mac_list != to_list(ffmac(mackey, to_element(challenge))):
            print("invalid mac")
            exit(1)
        key = os.urandom(k)
        ciphertext = encrypt(key, FLAG.encode())
        print(f"ciphertext: {ciphertext.hex()}")
        mac_key = ffmac(mackey, to_element(key))
        print(f"mac(key): {to_list(mac_key)}")
        exit(0)
    else:
        print("invalid option")
        exit(1)
```

There exists a finite field with order $p^{16}$ where $p = 2^{127} - 1$. `mackey` is a list of 6 field elements, and function `ffmac` is a function with one field element as input, and outputs one field element as well.

We can predict that the scenario is:
- Recover the `mackey` with option 1
- Pass the verification steps using `mackey` and recover `key` from the `mac(key)`

---

### 1. Function `ffmac`
First of all, we need to know how `ffmac` function works.
```python
def ffmac(key, x):
    k1, k2, k3, k4, k5, k6 = key
    l, r = k1, x
    for i in range(127):
        if i % 2:
            r = r * l * k2
            l = l * l
        else:
            l = l * r * k3
            r = r * r
        l, r = r, l
    return k4 * l + k5 * r * x + k6
```

We can think the result is a form of polynomials where variables are `x, k1, k2, k3, k4, k5, k6`. Thus, we can quickly construct a code that calculates the polynomial:
```python
P.<k1, k2, k3, k4, k5, k6, x> = PolynomialRing(QQ)

l, r = k1, x
for i in range(127):
    if i % 2:
        r = r * l * k2
        l = l * l
    else:
        l = l * r * k3
        r = r * r
    l, r = r, l

    print(f"{i}: {l}, {r}")
result = k4 * l + k5 * r * x + k6
```

Except the result doesn't seem too good.
```python
0: x^2, k1*k3*x
1: k1*k2*k3*x^3, x^4
2: x^8, k1*k2*k3^2*x^7
3: k1*k2^2*k3^2*x^15, x^16
4: x^32, k1*k2^2*k3^3*x^31
5: k1*k2^3*k3^3*x^63, x^64
6: x^128, k1*k2^3*k3^4*x^127
7: k1*k2^4*k3^4*x^255, x^256
8: x^512, k1*k2^4*k3^5*x^511
9: k1*k2^5*k3^5*x^1023, x^1024
10: x^2048, k1*k2^5*k3^6*x^2047
11: k1*k2^6*k3^6*x^4095, x^4096
12: x^8192, k1*k2^6*k3^7*x^8191
13: k1*k2^7*k3^7*x^16383, x^16384
14: x^32768, k1*k2^7*k3^8*x^32767
Traceback (most recent call last):
...
OverflowError: exponent overflow (65536)
```

We can unlimit the exponent surely, but there's no way it can hold exponent till $2^{127}$. But one thing we can notice here is that both of `l, r` consists on single term. During the for loop, there's only multiplication and no addition, which is why it stays as one term.

We slightly change the code so that we can see what variables consist those two terms, and how many times(exponent).
```python
# x, k1, k2, k3
l, r = vector([0, 1, 0, 0]), vector([1, 0, 0, 0])
for i in range(127):
    if i % 2:
        # r = r * l * k2
        r = r + l + vector([0, 0, 1, 0])
        # l = l * l
        l = l * 2
    else:
        # l = l * r * k3
        l = l + r + vector([0, 0, 0, 1])
        # r = r * r
        r = r * 2
    l, r = r, l

print(l, r)
```

```python
(170141183460469231731687303715884105728, 0, 0, 0) (170141183460469231731687303715884105727, 1, 63, 64)
```

This means after the for loop, `l, r` are the following:
```python
l = x^170141183460469231731687303715884105728
r = x^170141183460469231731687303715884105727 * k1 * k2^63 * k3^64
```

After the final step which is `k4 * l + k5 * r * x + k6`, the result is the following:
```python
(x^170141183460469231731687303715884105728) * (k4 + k1 * k2^63 * k3^64 * k5) + k6
```
We can simplify it to `x^(2^127) * a + b` where `a, b` is constant generated from `mackey`.

### 2. Recover `a, b` and get `mac(key)`
By using option 1 several times, we can get multiple result of `input^(2^128) * a + b`. Since we can calculate `input^(2^127)`, we can calculate `a, b` using linear equations of `F`.
```python
p = 2**127 - 1
k = 16
F = GF((p, k), "x")

from pwn import process, remote
from ast import literal_eval

io = process(["sage", "server.sage"])
# io = remote("34.170.146.252", 52907r)

xs = []

for i in range(3):
	msg = os.urandom(8).hex().encode()
	io.sendline(b"1")
	io.sendline(msg)
	xs.append(F(list(msg)))

res = []
for i in range(3):
	io.recvuntil(b"> input: mac(input): ")
	r = literal_eval(io.recvline().decode())
	res.append(F(r))

exp = 2^127

M = Matrix(F, [[xs[0]^exp, 1], [xs[1]^exp, 1], [xs[2]^exp, 1]])
r = vector(F, res)

root = M.solve_right(r)
a, b = root
```

And we pass some checks in option 2, which is easy to pass with value of `a, b`, and finally receive `mac(key)`! `t` represents `key^(2^127)` in the following code.
```python
io.sendline(b"2")
io.recvuntil(b"> challenge: ")

challenge = bytes.fromhex(io.recvline().decode())
ch = F(list(challenge))
mac = ch^exp * a + b
mac = str(list(mac))[1:-1].replace(" ", "")

io.sendline(mac.encode())

io.recvuntil(b"phertext: ")

ct = bytes.fromhex(io.recvline().decode())
io.recvuntil(b"mac(key): ")
mac = literal_eval(io.recvline().decode())
mac = F(mac)
io.close()

t = (mac - b) / a
```

### 3. Recover `key` from `key^(2^127)`
The multiplicative order of `F` is equal to $p^{16} - 1$, and our goal is to calculate `key` from `key^(127)`. However when I tried to calculate `d = pow(2^127, -1, p^16 - 1)`, like general RSA decryption, it says inverse doesn't exist because they're not coprime, which is bad.

Turns out they are not just coprime, but entirely a divisor: $2^{127} \mid p^{16} - 1$. The main reason of this is because $p = 2^{127} - 1$, so $2^{127} = p + 1$ and $p + 1 \mid p^{16} - 1$.

We know the a large number of candidates for `key` which satisfies `key^(2^127) = mackey`, specifically exactly $2^{127}$ candidates. The only clue left for `key` is that their coefficients are very small since it's from `os.urandom(16)`, so every coefficients has possible range `[0, 256)` instead of `[0, p)`.

> Here is the part where my approach differs from the intended solution, if you're interested in maple3142's intended solution using [Gröbner basis](https://en.wikipedia.org/wiki/Gr%C3%B6bner_basis), check out his write-up linked above!

We can find an arbitrary `r` where `r^(2^127) == t` simple using `nth_root` function. *Note: try finding root without using `nth_root` function! It would be a good practice to learn about rings.*
```python
r = t.nth_root(exp)
assert r^exp == t
```

Then for some field element $b$, the following equations holds:
$$
r^{p + 1} = t
$$
$$
b^{p + 1} = 1
$$
$$
r * b = k
$$

$k$ is the `key` as element, which has very small coefficients.

However, the smallest polynomial in form $p^d - 1$ which is a multiple of $p + 1$ isn't $p^{16} - 1$. We can see that $p^2 - 1$ also is a multiple of $p + 1$.

Which means every $p + 1$ possibilities of $b$ are also a $\mathbb{F}_{p^2}$ element as well.

Using some field cutting magic, let's execute the following:
```python
P.<x> = PolynomialRing(F)
root = P(GF(p^2).modulus()).roots()[0][0]
```
Then `root` represents the generator on $\mathbb{F}\_{p^2}$, but on $\mathbb{F}\_{p^{16}}$ ! Every $\mathbb{F}\_{p^2}$ elements can be written in form of `c1 * x + c2` where `x` is the generator and `aa, bb` are $\mathbb{F}\_{p}$ elements, we can finally conclude that every possible $b$ can be written in form of `c1 * root + c2`.

> This may be extermely hard to understand if you're not familiar with finite fields.  
I recommend some cool challenges related to this kind of field magic:  
**Cutter - Codegate 2023 Finals**  
**Quo vadis? - ECSC 2024 Italy**

So we learned that $b = c_1 * \textnormal{root} + c_2$, therefore $k = (r * \textnormal{root}) * c_1 + (r) * c_2$ holds where $c_1, c_2$ are $\mathbb{F}_{p}$ elements.

We can calculate $r * \textnormal{root}, r$ and by treating them as vector with length 16, this finally changes into a simple lattice problem!

> I will not deeply explain about how to construct lattice, or the LLL algorithm, since there are a lot of ways to construct them, and this is relatively a very basic lattice problem at this point.  
After you clear the Lattices course in CryptoHack, you will be able to understand this very easily!

We apply LLL, and finally recover the `key` to decrypt the flag.
```python
# answer = ? * d1 + ? * d2
d1 = list(r * root)
d2 = list(r)

M = Matrix(18, 18)
M[0, 0] = 1
M[1, 1] = 1

weight = 2^127 // 2^8

for i in range(16):
	M[0, 2 + i] = ZZ(d1[i]) * weight
	M[1, 2 + i] = ZZ(d2[i]) * weight
	M[2 + i, 2 + i] = p * weight

M = M.LLL()

for v in M:
	if v[-2] == 0:
		continue
	break

v = v[2:] / weight
if v[0] < 0:
	v = -v
key = bytes(list(v))

from Crypto.Cipher import AES

nonce, ct = ct[:8], ct[8:]
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
flag = cipher.decrypt(ct)
print(flag)
```

---

I really enjoyed this round of AlpacaHack CTF, thanks to the authors. Planning to attend the following Crypto rounds as well!