#pragma once

#include <botan-2/botan/ecdsa.h>
#include <botan-2/botan/ec_group.h>
#include <botan-2/botan/point_gfp.h>
#include <botan-2/botan/hash.h>
#include <botan-2/botan/bigint.h>
#include <botan-2/botan/rng.h>
#include <botan-2/botan/auto_rng.h>
#include <botan-2/botan/data_src.h>
#include <botan-2/botan/exceptn.h>
#include <botan-2/botan/oids.h>
#include <botan-2/botan/pubkey.h>
#include <botan-2/botan/ecc_key.h>
#include <botan-2/botan/hex.h>
#include <botan-2/botan/pk_keys.h>
#include <botan-2/botan/pkcs8.h>
#include <botan-2/botan/x509cert.h>
#include <botan-2/botan/pem.h>
#include <botan-2/botan/base64.h>

Botan::EC_Group m_group_domain("secp256k1");

Botan::BigInt getBigIntPrivateKey(std::string &sk_pem, const std::string &pass = "") {
    try {
        Botan::DataSource_Memory key_data(sk_pem);
        std::unique_ptr<Botan::Private_Key> key(Botan::PKCS8::load_key(key_data, pass));
        Botan::ECDSA_PrivateKey private_key(key->algorithm_identifier(), key->private_key_bits());
        return private_key.private_value();
    } catch (Botan::Exception &exception) {
        throw;
    }
}

Botan::PointGFp getPointPublicKey(std::string &pk_pem) {
    try {
        Botan::DataSource_Memory cert_datasource(pk_pem);
        Botan::X509_Certificate cert(cert_datasource);
        Botan::ECDSA_PublicKey public_key(cert.subject_public_key_algo(), cert.subject_public_key_bitstring());
        return public_key.public_point();
    } catch (Botan::Exception &exception) {
        throw;
    }
}

std::string hashMsg(std::string &msg) {
    std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create("SHA-256"));
    hash->update(msg);
    return Botan::base64_encode(hash->final_stdvec());
}

Botan::BigInt hash(std::string &msg) {
    std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create("SHA-256"));
    hash->update(msg);
    return Botan::BigInt::decode(hash->final_stdvec());
}

Botan::BigInt hash(const Botan::PointGFp &data) {
    std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create("SHA-256"));
    std::vector<uint8_t> encoded_point = data.encode(Botan::PointGFp::Compression_Type::UNCOMPRESSED);
    hash->update(encoded_point);
    Botan::BigInt temp;
    temp = Botan::BigInt::decode(hash->final_stdvec());
    return temp;
}

Botan::BigInt hash(const Botan::PointGFp &data, std::string &msg) {
    std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create("SHA-256"));
    std::vector<uint8_t> encoded_point = data.encode(Botan::PointGFp::Compression_Type::UNCOMPRESSED);
    hash->update(encoded_point);
    hash->update(msg);
    return Botan::BigInt::decode(hash->final_stdvec());
}

std::vector<int> computeNAF(Botan::BigInt &bigint) {
    std::vector<int> bit_string;
    int temp;

    while (bigint >= 1) {
        if(bigint % 2 == 0) {
            bit_string.emplace_back(0);
            bigint = bigint/2;
        } else {
            temp = 2 - (bigint % 4);

            if(temp == -1) {
                bit_string.emplace_back(2);
            } else {
                bit_string.emplace_back(temp);
            }

            if(temp == -1) {
                bigint += 1;
                bigint = bigint/2;
            } else {
                bigint -= temp;
                bigint = bigint/2;
            }
        }
    }
    return bit_string;
}

void pem_test() {
    std::string test_sk = R"(-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgBe+hD0dANH1UonOwQxqe
Fvc/J/C+8jTsqOtYSiQ+OamhRANCAAQ7U312c15p98EigrRri9+gp0BXvzSdhNUC
B2eSywdObeYu702dkOgHQ8rzpkUdj4TDMjItDR7fHshmfgaL3hWa
-----END PRIVATE KEY-----)";

    std::string test_pk = R"(-----BEGIN CERTIFICATE-----
MIIC4zCCAUugAwIBAgIRAJbcGDlLWBv36VTBSifZ90owDQYJKoZIhvcNAQELBQAw
PTEVMBMGA1UEAxMMLy8vLy8vLy8vLzg9MQswCQYDVQQGEwJLUjEXMBUGA1UEChMO
R3J1dXQgTmV0d29ya3MwHhcNMTkwMjI2MDIzNDUyWhcNMjAwMjI2MDIzNDUyWjAR
MQ8wDQYDVQQDEwZURVNUQ04wVjAQBgcqhkjOPQIBBgUrgQQACgNCAAQ7U312c15p
98EigrRri9+gp0BXvzSdhNUCB2eSywdObeYu702dkOgHQ8rzpkUdj4TDMjItDR7f
HshmfgaL3hWao1gwVjAhBgNVHQ4EGgQY0wM+4GWLF2ySLHkLMoBzTbg3MuAzbuy3
MAwGA1UdEwEB/wQCMAAwIwYDVR0jBBwwGoAYGCaqNIlvb/99LRAlk5JGHBjYKebe
jLP9MA0GCSqGSIb3DQEBCwUAA4IBgQAU2HtzzCIqlh4DvHbtcH6duH/nAPEyXmk1
4NXFgbQQjQTlmRAHzpjXcRxaIjpesy6iOzTR7Rf5Oo1nDj9fXks8wMdTdruajqTv
7NA2Wd4d6qgM30i2ss/ebJm1pSTL04hQM6XvEvyvYt7lgVV/GXvzgUoW8GDXSw3X
3upTGlDJEuLlILzFskOBYReKXhen6WjEL1qecXw9FNHpvzuzRZdPUQkeJX9cZZJz
F1iT28uBYX3YFDGW4x2THGxZOqp3ssdvuC/oTerBdrUTr8JiYIoVjy42StzWI6aC
vyqJbkalyPt5YgVlPtFy+Adv+mcUpQ9i8sYlfE3iUKxeJnMKpGgvjg8ppThVpVBt
TikN67sThXbzdOcEBrp1HksShTYgDYQ0go7zOcrM/tZJoSOsGrYL465luqAADuJR
U6sMCFVCluwL4+tP+pNyf79B2dwZdmtO90hOEODR7ue9qOGrTT2zmbgWpY1VnPD/
DocbVvQtIp+Hz4+8lSHaDy2N9TThUdo=
-----END CERTIFICATE-----)";

    Botan::BigInt sk = getBigIntPrivateKey(test_sk);
    Botan::PointGFp pk = getPointPublicKey(test_pk);
}

void convertPoint() {
    std::string x = "26833972284506131540286016591390535126456088067737141598304007534462041017965";
    std::string y = "104114881749017492131625145723439233859976050660014343027526103995029814908314";

    Botan::PointGFp point_ex = m_group_domain.point(Botan::BigInt(x), Botan::BigInt(y));
    std::vector<uint8_t> point_vec = point_ex.encode(Botan::PointGFp::COMPRESSED);

    std::string point_str(point_vec.begin(), point_vec.end());
    std::cout << point_str << std::endl;

    Botan::PointGFp decoded_point = m_group_domain.OS2ECP(point_vec);
    std::cout << "aff x : " << decoded_point.get_affine_x().to_dec_string() << std::endl;
    std::cout << "aff y : " << decoded_point.get_affine_y().to_dec_string() << std::endl;
}