from hashlib import sha512
from ecdsa import ellipticcurve, numbertheory
from ecdsa.ellipticcurve import Point
import socket
from Crypto.Cipher import ChaCha20

p = 30937339651019945892244794266256713890440922455872051984768764821736576084296075471241474533335191134590995377857533
a = 24699516740398840043612817898240834783822030109296416539052220535505263407290501127985941395251981432741860384780927
b = 24561086537518854907476957344600899117700350970429030091546712823181765905950742731855058586986320754303922826007424
x = 1305488802776637960515697387274764814560693662216913070824404729088258519836180992623611650289275235949409735080408
y = 2840284555446760004012395483787208388204705580027573689198385753943125520419959469842139003551394700125370894549378
n = 30937339651019945892244794266256713890440922455872051984762505561763526780311616863989511376879697740787911484829297

curve = ellipticcurve.CurveFp(p, a, b)
server_pubkey = Point(curve, 27688886377906486650974531457404629460190402224453915053124314392088359043897605198852944594715826578852025617899270, 20559737347380095279889465811846526151405412593746438076456912255094261907312918087801679069004409625818172174526443)
client_privkey = 168606034648973740214207039875253762473
# ECDH Shared secret
shared_secret = client_privkey * server_pubkey
# Chacha20 where the key and nonce are based on the SHA512 digest of the x-coordinate of the shared secret
secret = sha512(int.to_bytes(shared_secret.x(), 0x30, "big"))
cipher = ChaCha20.new(key=secret.digest()[:32], nonce=secret.digest()[32:40])

print(cipher.encrypt(b"verify\x00"))
print(cipher.encrypt(b"\x3f\xbd\x43\xda\x3e\xe3\x25"))
print(cipher.encrypt(b"\x86\xdf\xd7"))
print(cipher.encrypt(b"\xc5\x0c\xea\x1c\x4a\xa0\x64\xc3\x5a\x7f\x6e\x3a\xb0\x25\x84\x41\xac\x15\x85\xc3\x62\x56\xde\xa8\x3c\xac\x93\x00\x7a\x0c\x3a\x29\x86\x4f\x8e\x28\x5f\xfa\x79\xc8\xeb\x43\x97\x6d\x5b\x58\x7f\x8f\x35\xe6\x99\x54\x71\x16"))
print(cipher.encrypt(b"\xfc\xb1\xd2\xcd\xbb\xa9\x79\xc9\x89\x99\x8c"))
print(cipher.encrypt(b"\x61\x49\x0b"))
print(cipher.encrypt(b"\xce\x39\xda"))
print(cipher.encrypt(b"\x57\x70\x11\xe0\xd7\x6e\xc8\xeb\x0b\x82\x59\x33\x1d\xef\x13\xee\x6d\x86\x72\x3e\xac\x9f\x04\x28\x92\x4e\xe7\xf8\x41\x1d\x4c\x70\x1b\x4d\x9e\x2b\x37\x93\xf6\x11\x7d\xd3\x0d\xac\xba"))
print(cipher.encrypt(b"\x2c\xae\x60\x0b\x5f\x32\xce\xa1\x93\xe0\xde\x63\xd7\x09\x83\x8b\xd6"))
print(cipher.encrypt(b"\xa7\xfd\x35"))
print(cipher.encrypt(b"\xed\xf0\xfc"))
print(cipher.encrypt(b"\x80\x2b\x15\x18\x6c\x7a\x1b\x1a\x47\x5d\xaf\x94\xae\x40\xf6\xbb\x81\xaf\xce\xdc\x4a\xfb\x15\x8a\x51\x28\xc2\x8c\x91\xcd\x7a\x88\x57\xd1\x2a\x66\x1a\xca\xec"))
print(cipher.encrypt(b"\xae\xc8\xd2\x7a\x7c\xf2\x6a\x17\x27\x36\x85"))
print(cipher.encrypt(b"\x35\xa4\x4e"))
print(cipher.encrypt(b"\x2f\x39\x17"))
print(cipher.encrypt(b"\xed\x09\x44\x7d\xed\x79\x72\x19\xc9\x66\xef\x3d\xd5\x70\x5a\x3c\x32\xbd\xb1\x71\x0a\xe3\xb8\x7f\xe6\x66\x69\xe0\xb4\x64\x6f\xc4\x16\xc3\x99\xc3\xa4\xfe\x1e\xdc\x0a\x3e\xc5\x82\x7b\x84\xdb\x5a\x79\xb8\x16\x34\xe7\xc3\xaf\xe5\x28\xa4\xda\x15\x45\x7b\x63\x78\x15\x37\x3d\x4e\xdc\xac\x21\x59\xd0\x56"))
print(cipher.encrypt(b"\xf5\x98\x1f\x71\xc7\xea\x1b\x5d\x8b\x1e\x5f\x06\xfc\x83\xb1\xde\xf3\x8c\x6f\x4e\x69\x4e\x37\x06\x41\x2e\xab\xf5\x4e\x3b\x6f\x4d\x19\xe8\xef\x46\xb0\x4e\x39\x9f\x2c\x8e\xce\x84\x17\xfa"))
print(cipher.encrypt(b"\x40\x08\xbc"))
print(cipher.encrypt(b"\x54\xe4\x1e"))
print(cipher.encrypt(b"\xf7\x01\xfe\xe7\x4e\x80\xe8\xdf\xb5\x4b\x48\x7f\x9b\x2e\x3a\x27\x7f\xa2\x89\xcf\x6c\xb8\xdf\x98\x6c\xdd\x38\x7e\x34\x2a\xc9\xf5\x28\x6d\xa1\x1c\xa2\x78\x40\x84"))
print(cipher.encrypt(b"\x5c\xa6\x8d\x13\x94\xbe\x2a\x4d\x3d\x4d\x7c\x82\xe5"))
print(cipher.encrypt(b"\x31\xb6\xda\xc6\x2e\xf1\xad\x8d\xc1\xf6\x0b\x79\x26\x5e\xd0\xde\xaa\x31\xdd\xd2\xd5\x3a\xa9\xfd\x93\x43\x46\x38\x10\xf3\xe2\x23\x24\x06\x36\x6b\x48\x41\x53\x33\xd4\xb8\xac\x33\x6d\x40\x86\xef\xa0\xf1\x5e\x6e\x59"))
