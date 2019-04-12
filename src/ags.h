#pragma once

#include <iostream>
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
#include <botan-2/botan/pem.h>

class AGS {
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
    std::string a_aff_x;
    std::string a_aff_y;
};

private:
Botan::AutoSeeded_RNG m_rng;
Botan::EC_Group m_group_domain;
Botan::BigInt m_z;

public:
AGS() : m_group_domain("secp256k1") { }
~AGS() { }

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
    Botan::BigInt d_inv = m_group_domain.inverse_mod_order(d);
    Botan::BigInt z_mul_d_inv = m_group_domain.multiply_mod_order(z, d_inv);
    Botan::BigInt e_mul_d_inv = m_group_domain.multiply_mod_order(hash(pk, msg), d_inv);
    Botan::PointGFp A = m_group_domain.point_multiply(z_mul_d_inv, pk, e_mul_d_inv);

    if(hash(A) != d)
        return false;

    return true;
}

std::vector<AggregateSig> aggregate(std::vector<AggregateSet> &agg_set) {
    std::vector<AggregateSig> agg_sig;
    AggregateSig temp;
    Botan::BigInt d_inv;
    m_z.clear();
    Botan::PointGFp pk, a;
    std::vector<std::string> t_list;
    std::vector<std::string> a_list;
    std::string a_str, t_str;

    for(auto &item : agg_set) {
        if(!verify(item.pk_pem, item.msg, item.d, item.z))
            break;

        pk = getPublicKey(item.pk_pem);
        d_inv = m_group_domain.inverse_mod_order(item.d);
        temp.pk_pem = item.pk_pem;
        temp.msg = item.msg;
        a = m_group_domain.point_multiply(m_group_domain.multiply_mod_order(item.z, d_inv), pk, m_group_domain.multiply_mod_order(hash(pk, temp.msg), d_inv));
        temp.a_aff_x = a.get_affine_x().to_dec_string();
        temp.a_aff_y = a.get_affine_y().to_dec_string();
        m_z = m_group_domain.mod_order(m_z + item.z);

        t_str = item.pk_pem + item.msg;
        std::sort(t_list.begin(), t_list.end());
        if(!std::binary_search(t_list.begin(), t_list.end(), t_str))
            t_list.emplace_back(t_str);
        a_str = temp.a_aff_x + temp.a_aff_y;
        std::sort(a_list.begin(), a_list.end());
        if(!std::binary_search(a_list.begin(), a_list.end(), a_str))
            a_list.emplace_back(a_str);

        agg_sig.emplace_back(temp);
    }

    return agg_sig;
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

    if(!isUniqueElements(agg_set)) {
        return false;
    }

    size_t n = agg_set.size();
    size_t idx = 5;
    size_t rem = idx;
    size_t count = n/idx + 1;

    Botan::PointGFp tmp_a;

    for(size_t i = 0; i < count; ++i) {
        if(n < idx)
            rem = n;

        for(size_t j = 0+i*idx; j < rem+i*idx; ++j) {
            pk = getPublicKey(agg_set.at(j).pk_pem);
            tmp_a = m_group_domain.point(Botan::BigInt(agg_set.at(j).a_aff_x), Botan::BigInt(agg_set.at(j).a_aff_y));
            d_list.emplace_back(hash(tmp_a));
            e_list.emplace_back(hash(pk, agg_set.at(j).msg));
            pk_list.emplace_back(pk);
            a_list.emplace_back(tmp_a);
        }

        precomputed_table = precompute(pk_list);
        result += shamirTrick(e_list, precomputed_table);
        precomputed_table = precompute(a_list);
        result -= shamirTrick(d_list, precomputed_table);

        pk_list.clear();
        a_list.clear();
        d_list.clear();
        e_list.clear();
        n -= idx;
    }

    if(-z_mul_P != result)
        return false;

    return true;
}

private:
std::vector<Botan::PointGFp> precompute(std::vector<Botan::PointGFp> &point_list) {
    std::vector<Botan::PointGFp> precomputed_table;
    size_t num_p_size = std::pow(2, point_list.size());

    for(size_t i = 0; i < num_p_size; ++i) {
        Botan::PointGFp temp_point = m_group_domain.zero_point();
        std::bitset<10> precomputed_bit(i);

        for(size_t j = 0; j < point_list.size(); ++j) {
            if(precomputed_bit[j])
                temp_point += point_list.at(j);
        }

        precomputed_table.emplace_back(temp_point);
    }

    return precomputed_table;
}

Botan::PointGFp shamirTrick(std::vector<Botan::BigInt> &bigint_list,  std::vector<Botan::PointGFp> &precomputed_table) {
    Botan::PointGFp R = m_group_domain.zero_point();
    std::vector<Botan::BigInt> workspace(Botan::PointGFp::WORKSPACE_SIZE);
    int value = 0;
    size_t bigint_size = 0;
    std::vector<int> temp_vec;

    for(size_t i = 0; i < bigint_list.size(); ++i) {
        if(bigint_size < bigint_list.at(i).bits())
            bigint_size = bigint_list.at(i).bits();
    }

    for(int i = bigint_size-1; i >= 0; --i) {
        R.mult2(workspace);
        temp_vec.clear();

        for(int j = bigint_list.size() - 1; j >= 0; --j) {
            temp_vec.emplace_back(bigint_list.at(j).get_bit(i));
        }

        value = findIdx(temp_vec);

        if(value != 0)
            R += precomputed_table.at(value);
    }

    return R;
}

int findIdx(std::vector<int> &vec) {
    int temp = 0;

    for(size_t i = 0; i < vec.size(); ++i) {
        temp += vec.at(i) * std::pow(2, vec.size()-1-i);
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
    } catch (Botan::Exception &exception) {
        throw;
    }
}

bool isUniqueElements(std::vector<AggregateSig> &aggregate_set) {
    std::vector<std::string> t_list;
    std::vector<std::string> a_list;

    for(auto &item : aggregate_set) {
        t_list.emplace_back(item.pk_pem + item.msg);
        a_list.emplace_back(item.a_aff_x + item.a_aff_y);
    }

    std::sort(t_list.begin(), t_list.end());
    auto it_t = std::unique(t_list.begin(), t_list.end());
    if(it_t != t_list.end())
        return false;

    std::sort(a_list.begin(), a_list.end());
    auto it_a = std::unique(a_list.begin(), a_list.end());
    if(it_a != a_list.end())
        return false;

    if(t_list.size() != a_list.size())
        return false;

    return true;
}

};