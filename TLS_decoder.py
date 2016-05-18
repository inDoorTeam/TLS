import sys
import binascii
from decoder import *
if __name__ == "__main__":
    in1, in2, in3, out1, out2, = sys.argv[1:]
    f1 = open(in1, 'rb') # C2S
    f2 = open(in2, 'rb') # S2C
    content1 = f1.read()
    content2 = f2.read()
    f1.close()
    f2.close()
    hand_shake = b''
    requ_app_data = b''
    while len(content1) > 0:
        typ, ver1, ver2, len1, len2 = content1[:5]
        length = (len1 << 8) + len2
        fragmt = content1[5:5+length]
        if typ == 22:
            print('found a fragmt, ', len(fragmt))
            hand_shake += fragmt
            tail = fragmt
        elif typ == 23:
            requ_app_data += fragmt
        content1 = content1[5+length:]

    tail = len(hand_shake) - len(tail)
    cli_random = hand_shake[6:38]
    enc_pre_master = hand_shake[tail-256:tail]
    pre_master = RSA_DECRYPT(in3, enc_pre_master)
    hand_shake = b''
    resp_app_data = b''
    while len(content2) > 0:
        typ, ver1, ver2, len1, len2 = content2[:5]
        length = (len1 << 8) + len2
        fragmt = content2[5:5+length]
        if typ == 22:
            hand_shake += fragmt
        elif typ == 23:
            resp_app_data = fragmt
        content2 = content2[5+length:]
    ser_random = hand_shake[6:38]

    mast_secret   = TLS_PRF(pre_master,  str.encode("master secret"), cli_random + ser_random, 48)
    key_block     = TLS_PRF(mast_secret, str.encode("key expansion"), ser_random + cli_random, 104)
    cli_write_key = key_block[40:56] #16 bytes for a cli_write_key, 40 bytes 無視
    ser_write_key = key_block[56:72]
    cli_write_iv  = key_block[72:88] #16 bytes iv in AES_128_CBC
    ser_write_iv  = key_block[88:104]
    """
        client_write_MAC_key[SecurityParameters.mac_key_length]
        server_write_MAC_key[SecurityParameters.mac_key_length]
        client_write_key[SecurityParameters.enc_key_length]
        server_write_key[SecurityParameters.enc_key_length]
        client_write_IV[SecurityParameters.fixed_iv_length]
        server_write_IV[SecurityParameters.fixed_iv_length]

                                Key      IV   Block
        Cipher        Type    Material  Size  Size
        ------------  ------  --------  ----  -----
        NULL          Stream      0       0    N/A
        RC4_128       Stream     16       0    N/A
        3DES_EDE_CBC  Block      24       8      8
    --> AES_128_CBC   Block      16      16     16
        AES_256_CBC   Block      32      16     16

    """
    requ_app_data  = AES128CBC_DECRYPT(cli_write_key, cli_write_iv, requ_app_data)
    padding_length = requ_app_data[-1]
    requ_app_data  = requ_app_data[16:-21-padding_length] # 20 bytes for mac , 1 bytes for padding_length
    resp_app_data  = AES128CBC_DECRYPT(ser_write_key, ser_write_iv, resp_app_data)
    padding_length = resp_app_data[-1]
    resp_app_data  = resp_app_data[16:-21-padding_length] # 20 bytes for mac , 1 bytes for padding_length
    """
        struct {
            opaque IV[SecurityParameters.record_iv_length];
            block-ciphered struct {
                opaque content[TLSCompressed.length];
                opaque MAC[SecurityParameters.mac_length]; 20 bytes
                uint8 padding[GenericBlockCipher.padding_length];
                Wuint8 padding_length;
            };
        } GenericBlockCipher;

        MAC       Algorithm    mac_length  mac_key_length
        --------  -----------  ----------  --------------
        NULL      N/A              0             0
        MD5       HMAC-MD5        16            16
    --> SHA       HMAC-SHA1       20            20
        SHA256    HMAC-SHA256     32            32
    """
    print('client_random =', cli_random.hex())
    print('server_random =', ser_random.hex())
    print('encrypted_pre_master_secret =', enc_pre_master.hex())
    print('pre_master_secret =', pre_master.hex())
    print('master_secret =', mast_secret.hex())
    print('client_write_key =', cli_write_key.hex())
    print('server_write_key =', ser_write_key.hex())
    print('decrypt request result =', requ_app_data)
    print('decrypt response result =', resp_app_data)

    o1 = open(out1, 'wb')
    o1.write(requ_app_data)
    o1.close()
    o2 = open(out2, 'wb')
    o2.write(resp_app_data)
    o2.close()
