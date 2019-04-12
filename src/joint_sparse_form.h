#pragma once

#include <string>
#include <vector>
#include <algorithm>
#include <bitset>
#include <cmath>
#include <chrono>
#include <utility>

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

class JointSparseForm {
struct Key {
    Botan::BigInt sk;
    Botan::PointGFp pk;
};

struct Signature {
    Botan::BigInt d;
    Botan::BigInt z;
};

struct AggregateSet {
    std::string pk_pem;
    std::string msg;
    Botan::BigInt d;
    Botan::BigInt z;
};

struct AggregateSig {
    std::string pk_pem;
    std::string msg;
    Botan::PointGFp a;
};

struct JSF {
    std::vector<int> jsf_x;
    std::vector<int> jsf_y;
};

private:
Botan::AutoSeeded_RNG m_rng;
Botan::EC_Group m_group_domain;
Botan::BigInt m_z;

public:
JointSparseForm() : m_group_domain("secp256k1") { }

~JointSparseForm() { }

struct Sigma {
    Botan::BigInt d;
    Botan::BigInt z;
};

Key keyGen() {
    Key temp;
    temp.sk = m_group_domain.random_scalar(m_rng);
    std::vector<Botan::BigInt> temp_vec;
    temp.pk = m_group_domain.blinded_base_point_multiply(temp.sk, m_rng, temp_vec);
    return temp;
}

Signature sign(std::string &sk_pem, std::string &msg, const std::string &pass = "") {
    try {
        Botan::BigInt sk = getPrivateKey(sk_pem, pass);
        return sign(sk, msg);
    } catch (Botan::Exception &exception) {
        std::cout << "error on PEM to SK: " << exception.what() << std::endl;
    }
}

Signature sign(Botan::BigInt &sk, std::string &msg) {
    Signature sig;
    std::vector<Botan::BigInt> temp_vec;
    Botan::PointGFp pk = m_group_domain.blinded_base_point_multiply(sk, m_rng, temp_vec);
    Botan::BigInt r = m_group_domain.random_scalar(m_rng);
    Botan::PointGFp a = m_group_domain.blinded_base_point_multiply(r, m_rng, temp_vec);
    sig.d = hash(a);
    Botan::BigInt e = hash(pk, msg);
    sig.z = m_group_domain.mod_order(m_group_domain.multiply_mod_order(r, sig.d) - m_group_domain.multiply_mod_order(e, sk));
    return sig;
}

bool verify(std::string &pk_pem, std::string &msg, Botan::BigInt &d, Botan::BigInt &z) {
    try {
        Botan::PointGFp pk = getPublicKey(pk_pem);
        return verify(pk, msg, d, z);
    } catch (Botan::Exception &exception) {
        std::cout << "error on PEM to PK: " << exception.what() << std::endl;
        return false;
    }
}

bool verify(Botan::PointGFp &pk, std::string &msg, Botan::BigInt &d, Botan::BigInt &z) {
    Botan::BigInt d_inverse = m_group_domain.inverse_mod_order(d);
    Botan::BigInt z_mul_d_inverse = m_group_domain.multiply_mod_order(z, d_inverse);
    Botan::BigInt e_mul_d_inverse = m_group_domain.multiply_mod_order(hash(pk, msg), d_inverse);
    Botan::PointGFp A = m_group_domain.point_multiply(z_mul_d_inverse, pk, e_mul_d_inverse);

    if(hash(A) != d)
        return false;

    return true;
}

private:
JSF simpleJointSparseForm(Botan::BigInt &x, Botan::BigInt &y) {
    JSF temp;
    int temp_x = 0;
    int temp_y = 0;

    while(x != 0 || y != 0) {
        temp_x = x % 2;
        temp_y = y % 2;

        if(temp_x == 1 && temp_y == 1) {
            if((x-temp_x)/2 % 2 == 1)
                temp_x = -temp_x;

            if((y-temp_y)/2 % 2 == 1)
                temp_y = -temp_y;
        } else if(temp_x != temp_y) {
            if((x-temp_x)/2 % 2 != (y-temp_y)/2 % 2) {
                temp_x = -temp_x;
                temp_y = -temp_y;
            }
        }

        if(temp_x == -1) {
            x = (x+1) / 2;
        } else {
            x = (x-temp_x) / 2;
        }

        if(temp_y == -1) {
            y = (y+1) / 2;
        } else {
            y = (y-temp_y) / 2;
        }

        if(temp_x == -1) {
            temp.jsf_x.emplace_back(2);
        } else {
            temp.jsf_x.emplace_back(temp_x);
        }
        if(temp_y == -1) {
            temp.jsf_y.emplace_back(2);
        } else {
            temp.jsf_y.emplace_back(temp_y);
        }
    }

    return temp;
}

Botan::BigInt hash(Botan::PointGFp &point) {
    std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create("SHA-256"));
    hash->update(point.get_affine_x().to_hex_string());
    hash->update(point.get_affine_y().to_hex_string());
    return Botan::BigInt::decode(hash->final_stdvec());
}

Botan::BigInt hash(Botan::PointGFp &point, std::string &msg) {
    std::unique_ptr<Botan::HashFunction> hash(Botan::HashFunction::create("SHA-256"));
    hash->update(point.get_affine_x().to_hex_string());
    hash->update(point.get_affine_y().to_hex_string());
    hash->update(msg);
    return Botan::BigInt::decode(hash->final_stdvec());
}

Botan::BigInt hash(std::string &pk_pem, std::string &msg) {
    try {
        Botan::PointGFp pk = getPublicKey(pk_pem);
        return hash(pk, msg);
    } catch(Botan::Exception &exception) {
        throw;
    }
}

Botan::BigInt getPrivateKey(std::string &sk_pem, const std::string &pass = "") {
    try {
        Botan::DataSource_Memory key_data(sk_pem);
        std::unique_ptr<Botan::Private_Key> key(Botan::PKCS8::load_key(key_data, pass));
        Botan::ECDSA_PrivateKey private_key(key->algorithm_identifier(), key->private_key_bits());
        return private_key.private_value();
    } catch (Botan::Exception &exception) {
        throw;
    }
}

Botan::PointGFp getPublicKey(std::string &pk_pem) {
    try {
        Botan::DataSource_Memory cert_datasource(pk_pem);
        Botan::X509_Certificate cert(cert_datasource);
        Botan::ECDSA_PublicKey public_key(cert.subject_public_key_algo(), cert.subject_public_key_bitstring());
        return public_key.public_point();
    } catch(Botan::Exception &exception) {
        throw;
    }
}

bool aggregateVerify(std::vector<AggregateSig> &agg_set, Botan::BigInt &sum_of_z) {
    std::vector<Botan::BigInt> d_list;
    std::vector<Botan::BigInt> e_list;
    std::vector<Botan::PointGFp> pk_list;
    std::vector<Botan::PointGFp> a_list;
    std::vector<Botan::BigInt> temp_vec;

    Botan::PointGFp z_mul_P = m_group_domain.blinded_base_point_multiply(sum_of_z, m_rng, temp_vec);
    Botan::PointGFp result = m_group_domain.zero_point();
    std::vector<Botan::PointGFp> precomputed_table;
    Botan::PointGFp pk;

    size_t n = agg_set.size();
    size_t idx = 2;
    size_t count = n/idx + 1;

    for(size_t i = 0; i < count; ++i) {
        if(n < idx)
            idx = n;

        for(size_t j = 0+i*2; j < idx+i*2; ++j) {
            pk = getPublicKey(agg_set.at(j).pk_pem);
            d_list.emplace_back(hash(agg_set.at(j).a));
            e_list.emplace_back(hash(pk, agg_set.at(j).msg));
            pk_list.emplace_back(pk);
            a_list.emplace_back(agg_set.at(j).a);
        }

        precomputed_table = precomputeJSF(pk_list);
        result += shamirTrickWithJSF(e_list, precomputed_table);
        precomputed_table = precomputeJSF(a_list);
        result -= shamirTrickWithJSF(d_list, precomputed_table);

        pk_list.clear();
        a_list.clear();
        d_list.clear();
        e_list.clear();

        n -= idx;
    }

    if(-z_mul_P != result) {
        return false;

    return true;
}

Botan::PointGFp shamirTrickWithJSF(std::vector<Botan::BigInt> &bigint_list, std::vector<Botan::PointGFp> &precomputed_table) {
    Botan::PointGFp R = m_group_domain.zero_point();
    std::vector<Botan::BigInt> workspace(Botan::PointGFp::WORKSPACE_SIZE);
    int value = 0;
    std::vector<int> temp_vec;
    int jsf_size = 0;

    std::vector<std::vector<int>> jsf_vec;
    JSF temp_jsf;

    for(size_t i = 0; i < bigint_list.size()/2; ++i) {
        temp_jsf = simpleJointSparseForm(bigint_list.at(2*i), bigint_list.at(2*i + 1));

        jsf_vec.emplace_back(temp_jsf.jsf_x);
        if((unsigned)jsf_size < jsf_vec.back().size()) {
            jsf_size = jsf_vec.back().size();
        }
        jsf_vec.emplace_back(temp_jsf.jsf_y);
        if((unsigned)jsf_size < jsf_vec.back().size()) {
            jsf_size = jsf_vec.back().size();
        }
    }

    for(int i = jsf_size-1; i >= 0; --i) {
        R.mult2(workspace);
        temp_vec.clear();

        for(size_t j = 0; j < bigint_list.size(); ++j) {
            if((unsigned)i >= jsf_vec[j].size()) {
                temp_vec.emplace_back(0);
            } else {
                temp_vec.emplace_back(jsf_vec[j].at(i));
            }
        }

        value = findIdx(temp_vec);

        if(value != 0) {
            R += precomputed_table.at(value);
        }
    }

    return R;
}

int findIdx(std::vector<int> &vec) {
    int temp = 0;

    for(size_t i = 0; i < vec.size(); ++i) {
        temp += vec.at(i) * std::pow(3, vec.size()-1-i);
    }

    return temp;
}

std::vector<Botan::PointGFp> precomputeJSF(std::vector<Botan::PointGFp> &point_list) {
    std::vector<Botan::PointGFp> precomputed_table;
    std::vector<int> precomputed_idx;
    int num_p_size = std::pow(3, point_list.size());

    for(size_t i = 0; i < point_list.size(); ++i) {
        precomputed_idx.emplace_back(0);
    }
    for(int i = 0; i < num_p_size; ++i) {
        Botan::PointGFp temp = m_group_domain.zero_point();

        for(size_t j = 0; j < point_list.size(); ++j) {
            if(precomputed_idx.at(j) == 1) {
                temp += point_list.at(j);
            } else if(precomputed_idx.at(j) == 2) {
                temp -= point_list.at(j);
            }
        }

        precomputed_table.emplace_back(temp);
        inc(precomputed_idx);
    }

    return precomputed_table;
}

std::vector<int> inc(std::vector<int> &vec) {
    for(int i = vec.size()-1; i >= 0; --i) {
        if(vec[i] == 0) {
            vec[i] = 1;
            break;
        } else if(vec[i] == 1) {
            vec[i] = 2;
            break;
        }
        vec[i] = 0;
    }

    return vec;
}

};