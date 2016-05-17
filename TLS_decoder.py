import sys
def B2I(b):
    assert type(b) is bytes
    return int.from_bytes(b, byteorder='big')

def I2B(i, length):
    assert type(i) is int
    assert type(length) is int and length >= 0
    return int.to_bytes(i, length, byteorder='big')

def HMAC_SHA256(key, msg):
    import hmac
    return hmac.new(key, msg, 'sha256').digest()

def SYSTEM(command, stdin=None):
    from subprocess import Popen, PIPE
    proc = Popen(command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = proc.communicate(stdin)
    return stdout, stderr, proc.returncode

def RSA_DECRYPT(skfilename, ciphertext):
    assert type(skfilename) is str
    assert type(ciphertext) is bytes
    stdout, stderr, retcode = SYSTEM((
        'openssl', 'rsautl', '-decrypt', '-inkey', skfilename
    ), ciphertext)
    assert retcode == 0 and stderr == b''
    return stdout

def TLS_PRF(secret, label, seed, n_bytes):
    assert type(secret) is bytes
    assert type(label) is bytes
    assert type(seed) is bytes
    assert type(n_bytes) is int and n_bytes >= 0
    last_A = label + seed
    result = b''
    while len(result) < n_bytes:
        last_A = HMAC_SHA256(secret, last_A)
        result += HMAC_SHA256(secret, last_A + label + seed)
    return result[:n_bytes]

def AES128CBC_DECRYPT(secret_key, ini_vector, ciphertext):
    assert type(secret_key) is bytes and len(secret_key) == 16
    assert type(ini_vector) is bytes and len(ini_vector) == 16
    assert type(ciphertext) is bytes and len(ciphertext) % 16 == 0
    stdout, stderr, retcode = SYSTEM((
        'openssl', 'enc', '-aes-128-cbc', '-d', '-nopad',
        '-K', ''.join('%02x'%x for x in secret_key),
        '-iv', ''.join('%02x'%x for x in ini_vector)
    ), ciphertext)
    assert retcode == 0 and stderr == b''
    return stdout
if __name__ == "__main__":
    in1, in2, in3, out1, out2, = sys.argv[1:]
    f1 = open(in1, 'rb') # C2S
    f2 = open(in2, 'rb') # S2C
    content1 = f1.read()
    content2 = f2.read()
    f1.close()
    f2.close()

    hand_shake = b''
    while len(content1) > 0:
        typ, ver1, ver2, len1, len2 = content1[:5]
        length = (len1 * 256) + len2
        fragmt = content1[5:5+length]
        tail   = content1[5+length:]
        if typ == 22:
            #print('found one record with length = ',length)
            hand_shake += fragmt
        content1 = content1[5+length:]

    cli_random = hand_shake[6:38]
    print('client_random =', cli_random.hex())

    hand_shake = b''
    while len(content2) > 0:
        typ, ver1, ver2, len1, len2 = content2[:5]
        length = (len1 * 256) + len2
        fragmt = content2[5:5+length]
        tail   = content2[5+length:]
        if typ == 22:
            #print('found one record with length = ',length)
            hand_shake += fragmt
        content2 = content2[5+length:]

    ser_random = hand_shake[6:38]
    print('server_random =', ser_random.hex())
