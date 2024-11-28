from binascii import hexlify, unhexlify
from Crypto.Hash import keccak
import nacl.bindings

import monero.base58 as base58

edwards_add = nacl.bindings.crypto_core_ed25519_add
inv = nacl.bindings.crypto_core_ed25519_scalar_invert
scalar_add = nacl.bindings.crypto_core_ed25519_scalar_add
scalarmult_B = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp
scalarmult = nacl.bindings.crypto_scalarmult_ed25519_noclamp
def scalar_reduce(v):
    return nacl.bindings.crypto_core_ed25519_scalar_reduce(v + (64 - len(v)) * b"\0")

def keccak_hash(data):
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()

def get_address_final(baseaddress, secret_vk, major, minor):
    # ensure indexes are within uint32
    if major < 0 or major >= 2**32:
        raise ValueError("major index {} is outside uint32 range".format(major))
    if minor < 0 or minor >= 2**32:
        raise ValueError("minor index {} is outside uint32 range".format(minor))
    if major == minor == 0:
        return baseaddress
    master_svk = unhexlify(secret_vk)
    master_psk = unhexlify(base58.decode(baseaddress)[2:66])
    # m = Hs("SubAddr\0" || master_svk || major || minor)
    hsdata = b"".join(
        [
            b"SubAddr\0",
            master_svk,
            major.to_bytes(4, byteorder='little'),
            minor.to_bytes(4, byteorder='little'),
        ]
    )
    m = keccak_hash(hsdata)
    # D = master_psk + m * B
    D = edwards_add(
        master_psk, scalarmult_B(scalar_reduce(m))
    )
    # C = master_svk * D
    C = scalarmult(master_svk, D)
    data = bytearray(b'*') + D + C
    checksum = keccak_hash(data)[:4]
    return base58.encode(hexlify(data + checksum))



baseaddress = ''
secret_vk = ''

print(get_address_final(baseaddress, secret_vk, 0, 1))


