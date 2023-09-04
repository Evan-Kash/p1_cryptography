from pysha256 import sha256, padding
m = 'Use HMAC, not hashes'.encode()  # .encode() converts str to bytes
h1 = sha256()
h1.update(m)
padded_message_len = len(m) + len(padding(len(m)))
h2 = sha256(
    state=bytes.fromhex('8f36ee4a3885bcc8a8446b09e9498808c97667f0266e3641c5d2abca457f9187'),
    count=padded_message_len,
)
x = 'Good advice'.encode()  # .encode() converts str to bytes
h2.update(x)
print(h2.hexdigest() + '\n')
print(sha256(m + x).hexdigest())