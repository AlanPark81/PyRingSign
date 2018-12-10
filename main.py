import hashlib, random, os
from Crypto.PublicKey import RSA
from Crypto import Random

N = 4
L = 1024
ll = 1 << (L - 1)


def generate_keys(n):
    key_list = [None] * n
    for i in range(n):
        key_list[i] = RSA.generate(1024, Random.new().read)
    return key_list


def pick_random_x_list(n, z):
    x_list = [None] * n
    for i in list(range(z))+list(range(z+1, n)):
        x_list[i] = random.randint(0, 1024)
    return x_list


def g(x, pub_key):
    return pub_key.encrypt(x, 1234)[0] % ll


def E(k, y, e):
    return k ^ y ^ e


def calculate_y_list(x_list, pubkey_list, z):
    ret_list = [None] * len(x_list)
    for i in list(range(z))+list(range(z+1, len(pubkey_list))):
        ret_list[i] = g(x_list[i], pubkey_list[i])
    return ret_list


def sign(m, n, s, p):
    k = int(hashlib.sha1(m.encode()).hexdigest(), 16)
    v = random.randint(0, 1024)
    x_list = pick_random_x_list(n, s)
    y_list = calculate_y_list(x_list, p, s)

    temp = v

    for i in list(range(s))+list(range(s+1, n)):
        temp = E(k, y_list[i], temp)
    temp ^= k
    y_list[s] = temp ^ v
    key = RSA.generate(1024, Random.new().read)
    pubkey = key.publickey()
    p[s] = pubkey
    x_list[s] = key.decrypt(y_list[s])
    return p, v, x_list


def verify(m, p, v, x_list):
    y_list = [None] * len(x_list)
    for i in range(len(x_list)):
        y_list[i] = g(x_list[i], p[i])
    k = int(hashlib.sha1(m.encode()).hexdigest(), 16)
    temp = v
    for i in range(len(y_list)):
        temp = E(k, y_list[i], temp)
    return temp


key_list = generate_keys(N)
p = [None] * N

for i in list(range(2))+list(range(2+1, N)):
    p[i] = key_list[i].publickey()

plain_text = "helsdklfjhasldkjhasdkljgaslkdgfaldjhadskhflkasdhflakdflaksjdhaklsjfhalkfalskjfakljdfhlo"

count = 10000
result_list = []
for i in range(count):
    pubkey_list, v, x_array = sign(plain_text,
                                   N, 2, p)
    temp = verify(
        plain_text, pubkey_list, v, x_array)
    assert (temp == v)
    result_list.append(temp)

result_list.sort()

import collections
print(len([item for item, count in collections.Counter(result_list).items() if count > 1]))
