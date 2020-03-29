/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 *
 * This file is part of libcornet.
 *
 *  libcornet is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  libcornet is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with libcornet.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <memory>
#include <libcornet/tls/crypto/tls_handshake.hpp>

#include <cassert>
#include <algorithm>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <libcornet/tls/crypto/hkdf.hpp>
#include <libcornet/tls/crypto/record_cryptor.hpp>

namespace pioneer19::cornet::tls13::crypto
{

TlsHandshake::TlsHandshake( RecordCryptor& record_cryptor, std::string& sni )
        :accept_sni{&sni},m_record_cryptor{record_cryptor},m_messages_digest{ EVP_MD_CTX_new() }
{}

TlsHandshake::TlsHandshake( RecordCryptor& record_cryptor, const std::string& sni, record::NamedGroup named_group )
        :connect_sni{&sni},m_record_cryptor{record_cryptor},m_messages_digest{ EVP_MD_CTX_new() }, m_named_group{ named_group }
{}

TlsHandshake::~TlsHandshake() noexcept
{
    EVP_MD_CTX_free( m_messages_digest );
}

void TlsHandshake::set_handshake_hello_key_share(
        record::NamedGroup named_group, const uint8_t* public_key, uint16_t key_size ) noexcept
{
    dhe_shared_secret_size = m_named_group.derive_secret(
            named_group, public_key, key_size, dhe_shared_secret );
    assert( dhe_shared_secret_size < sizeof(dhe_shared_secret) );
}

void TlsHandshake::derive_client_server_traffic_secrets( bool from_server ) noexcept
{
    const uint8_t* early_secret = empty_early_secret( m_record_cryptor.m_tls_cipher_suite.digest() );

    init_handshake_stage_data();

    // Derive-Secret(Early Secret, "derived", "")
    uint8_t handshake_secret_salt[EVP_MAX_MD_SIZE];
    const uint8_t derived_label[] = "derived";
    derive_secret( m_record_cryptor.m_tls_cipher_suite.digest()
            ,early_secret, m_record_cryptor.m_tls_cipher_suite.digest_size()
            ,derived_label, sizeof(derived_label)-1, nullptr, 0
            ,handshake_secret_salt );
    // (EC)DHE -> HKDF-Extract = Handshake Secret
    hkdf_extract( m_record_cryptor.m_tls_cipher_suite.digest()
                  ,handshake_secret_salt, m_record_cryptor.m_tls_cipher_suite.digest_size()
                  ,dhe_shared_secret, dhe_shared_secret_size
                  , m_handshake_secret );
    /*
     * Derive-Secret(., "c hs traffic",ClientHello...ServerHello)
     *         = client_handshake_traffic_secret
     * Derive-Secret(Secret, Label, Messages) =
     *          HKDF-Expand-Label(Secret, Label,
     *                            Transcript-Hash(Messages), Hash.length)
     */
    uint8_t client_server_messages_hash[ EVP_MAX_MD_SIZE ];
    current_transcript_hash( client_server_messages_hash );

    uint8_t c_hs_traffic_label[] = "c hs traffic";
    hkdf_expand_label( m_record_cryptor.m_tls_cipher_suite.digest()
                       ,m_handshake_secret, m_record_cryptor.m_tls_cipher_suite.digest_size()
                       ,c_hs_traffic_label, sizeof(c_hs_traffic_label) - 1
                       ,client_server_messages_hash, m_record_cryptor.m_tls_cipher_suite.digest_size()
                       ,m_client_handshake_traffic_secret
                       ,m_record_cryptor.m_tls_cipher_suite.digest_size() );
    /*
     * Derive-Secret(., "s hs traffic", ClientHello...ServerHello)
     *         = server_handshake_traffic_secret
     */
    const uint8_t s_hs_traffic_label[] = "s hs traffic";
    hkdf_expand_label( m_record_cryptor.m_tls_cipher_suite.digest()
                       ,m_handshake_secret, m_record_cryptor.m_tls_cipher_suite.digest_size()
                       ,s_hs_traffic_label, sizeof(s_hs_traffic_label) - 1
                       ,client_server_messages_hash, m_record_cryptor.m_tls_cipher_suite.digest_size()
                       ,m_server_handshake_traffic_secret
                       ,m_record_cryptor.m_tls_cipher_suite.digest_size() );
    /*
     * [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
     * [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)
     */
    // FIXME: now sender == client
    const uint8_t key_label[] = "key";
    const uint8_t iv_label[] = "iv";
    uint8_t* sender_traffic_secret   = nullptr;
    uint8_t* receiver_traffic_secret = nullptr;
    if( from_server )
    {
        sender_traffic_secret   = m_client_handshake_traffic_secret;
        receiver_traffic_secret = m_server_handshake_traffic_secret;
    }
    else
    {
        sender_traffic_secret   = m_server_handshake_traffic_secret;
        receiver_traffic_secret = m_client_handshake_traffic_secret;
    }
    // sender key and iv
    hkdf_expand_label( m_record_cryptor.m_tls_cipher_suite.digest()
                       ,sender_traffic_secret
                       ,m_record_cryptor.m_tls_cipher_suite.digest_size()
                       ,key_label, sizeof(key_label)-1, nullptr, 0
                       ,m_record_cryptor.m_tls_cipher_suite.sender_key_data(), m_record_cryptor.m_tls_cipher_suite.key_size() );
    hkdf_expand_label( m_record_cryptor.m_tls_cipher_suite.digest()
                       ,sender_traffic_secret
                       ,m_record_cryptor.m_tls_cipher_suite.digest_size()
                       ,iv_label, sizeof(iv_label)-1, nullptr, 0
                       ,m_record_cryptor.m_tls_cipher_suite.sender_iv_data(), m_record_cryptor.m_tls_cipher_suite.iv_size() );
    // receiver key and iv
    hkdf_expand_label( m_record_cryptor.m_tls_cipher_suite.digest()
                       ,receiver_traffic_secret
                       ,m_record_cryptor.m_tls_cipher_suite.digest_size()
                       ,key_label, sizeof(key_label)-1, nullptr, 0
                       ,m_record_cryptor.m_tls_cipher_suite.receiver_key_data(), m_record_cryptor.m_tls_cipher_suite.key_size() );
    hkdf_expand_label( m_record_cryptor.m_tls_cipher_suite.digest()
                       ,receiver_traffic_secret
                       ,m_record_cryptor.m_tls_cipher_suite.digest_size()
                       ,iv_label, sizeof(iv_label)-1, nullptr, 0
                       ,m_record_cryptor.m_tls_cipher_suite.receiver_iv_data(), m_record_cryptor.m_tls_cipher_suite.iv_size() );
    m_record_cryptor.m_tls_cipher_suite.reset_key_counters();
}

/**
 * Early secret without PSK
 * @return HKDF-Extract(0, 0)
 */
const uint8_t* TlsHandshake::empty_early_secret( const EVP_MD* md ) noexcept
{
    struct EmptyEarlySecret {
        uint8_t early_secret[EVP_MAX_MD_SIZE];
        EmptyEarlySecret( const EVP_MD* md, uint8_t* zeroes )
        {
            hkdf_extract( md, zeroes, 0
                  ,zeroes, EVP_MD_size(md), early_secret );
        }
    };

    static uint8_t zeros_size_of_hash_len[EVP_MAX_MD_SIZE] = {0};
    static EmptyEarlySecret early256{ EVP_sha256(), zeros_size_of_hash_len };
    static EmptyEarlySecret early384{ EVP_sha384(), zeros_size_of_hash_len };

    if( md == EVP_sha256() )
        return early256.early_secret;
    else if( md == EVP_sha384() )
        return early384.early_secret;

    static thread_local uint8_t early_secret[EVP_MAX_MD_SIZE];
    size_t md_size = EVP_MD_size(md);

    hkdf_extract( md, zeros_size_of_hash_len, 0
                  ,zeros_size_of_hash_len, md_size, early_secret );

    return early_secret;
}

void TlsHandshake::set_tls_cipher_suite( record::CipherSuite cipher_suite )
{
    m_record_cryptor.m_tls_cipher_suite.set_cipher_suite( cipher_suite );
    EVP_DigestInit_ex( m_messages_digest, m_record_cryptor.m_tls_cipher_suite.digest(), nullptr );

    m_cipher_suite = cipher_suite;
}

uint32_t TlsHandshake::current_transcript_hash( uint8_t* hash_out ) const noexcept
{
    EVP_MD_CTX *messages_hash_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_copy( messages_hash_ctx, m_messages_digest );
    uint32_t hash_size = EVP_MAX_MD_SIZE;
    EVP_DigestFinal_ex( messages_hash_ctx, hash_out, &hash_size );
    EVP_MD_CTX_free( messages_hash_ctx );

    return hash_size;
}

uint32_t TlsHandshake::handshake_finished_create_verify_data( uint8_t* hmac_data, bool from_server )
{
    uint8_t finished_key[EVP_MAX_MD_SIZE];
    /*
     * finished_key =
     *     HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
     */
    const uint8_t finished_label[] = "finished";
    const EVP_MD* digest = m_record_cryptor.m_tls_cipher_suite.digest();
    uint32_t digest_size = m_record_cryptor.m_tls_cipher_suite.digest_size();
    const uint8_t* traffic_secret = nullptr;

    if( from_server )
        traffic_secret = m_server_handshake_traffic_secret;
    else
        traffic_secret = m_client_handshake_traffic_secret;

    crypto::hkdf_expand_label( digest
                               , traffic_secret, digest_size
                               , finished_label, sizeof( finished_label ) - 1
                               , nullptr, 0
                               , finished_key, digest_size );
    /*
     * verify_data =
     *     HMAC(finished_key,
     *          Transcript-Hash(Handshake Context,
     *                          Certificate, CertificateVerify))
     */
    uint8_t transcript_hash[EVP_MAX_MD_SIZE];
    current_transcript_hash( transcript_hash );

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key( EVP_PKEY_HMAC, nullptr, finished_key, digest_size );
    if( pkey == nullptr )
    {
        ERR_print_errors_fp( stderr );
        return 0;
    }
    EVP_DigestSignInit( md_ctx, nullptr, digest, nullptr, pkey );
    EVP_DigestSignUpdate( md_ctx, transcript_hash, digest_size );
    size_t calculated_size = 0;
    if( EVP_DigestSignFinal( md_ctx, hmac_data, &calculated_size ) != 1 )
    {
        ERR_print_errors_fp( stderr );
        return 0;
    }

    return calculated_size;
}

uint32_t TlsHandshake::handshake_certificate_verify_create_signed_data(
        uint8_t* signed_data, bool from_server )
{
    /*
     * The digital signature is computed over the concatenation of:
     * -  A string that consists of octet 32 (0x20) repeated 64 times
     * -  The context string
     * -  A single 0 byte which serves as the separator
     * -  Transcript-Hash including Certificate message
     */
    std::fill( signed_data, signed_data+64, 0x20 );

    static const uint8_t server_sign_context_string[] = "TLS 1.3, server CertificateVerify";
    static const uint8_t client_sign_context_string[] = "TLS 1.3, client CertificateVerify";

    constexpr uint32_t context_string_size = sizeof(server_sign_context_string)-1;
    const uint8_t* context_string = nullptr;
    if( from_server )
        context_string = server_sign_context_string;
    else
        context_string = client_sign_context_string;

    auto context_string_offset = 64;
    std::copy_n( context_string, context_string_size+1, signed_data+context_string_offset );

    auto hash_offset = context_string_offset + context_string_size + 1;
    auto hash_size = current_transcript_hash( signed_data + hash_offset );

    uint32_t signed_data_size = hash_offset + hash_size;
    return signed_data_size;
}

uint32_t TlsHandshake::handshake_certificate_verify_sign_data( uint8_t* signature, uint32_t signature_size,
                                                               const uint8_t* data_to_sign, uint32_t data_size, EVP_PKEY* pkey, int nid, const EVP_MD* md )
{
    assert( EVP_PKEY_id( pkey ) == nid );
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();

    EVP_PKEY_CTX* pkey_ctx = nullptr;
    EVP_DigestSignInit( md_ctx, &pkey_ctx, md, nullptr, pkey );

    // needed for rsa_pss_{pss,rsae} algorithms
    if( nid == NID_rsaEncryption || nid == NID_rsassaPss )
    {
        EVP_PKEY_CTX_set_rsa_padding( pkey_ctx, RSA_PKCS1_PSS_PADDING );
        EVP_PKEY_CTX_set_rsa_pss_saltlen( pkey_ctx, RSA_PSS_SALTLEN_DIGEST);
    }
    size_t tmp_size = signature_size;
    if( EVP_DigestSign( md_ctx, signature, &tmp_size, data_to_sign, data_size ) != 1 )
    {
        char err_buffer[1024];
        std::string err_string{ ERR_error_string( ERR_get_error(), err_buffer ) };
        throw std::runtime_error(
                "TlsHandshake::handshake_certificate_verify_sign_data failed EVP_DigestSign" + err_string );
    }
    EVP_MD_CTX_free( md_ctx );
    printf( "certificate_verify_sign_data size %lu\n", tmp_size );

    return tmp_size;
}

bool TlsHandshake::handshake_check_signed_data(
        const uint8_t* signature, uint32_t signature_size
        , const uint8_t* signed_data, uint32_t signed_data_size
        , int nid, const EVP_MD* md )
{
    EVP_PKEY* pkey = X509_get0_pubkey( m_certificate );
    if( EVP_PKEY_id( pkey ) != nid )
        return false;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();

    EVP_PKEY_CTX* pkey_ctx = nullptr;
    EVP_DigestVerifyInit( md_ctx, &pkey_ctx, md, nullptr, pkey );

    // needed for rsa_pss_{pss,rsae} algorithms
    if( nid == NID_rsaEncryption || nid == NID_rsassaPss )
    {
        EVP_PKEY_CTX_set_rsa_padding( pkey_ctx, RSA_PKCS1_PSS_PADDING );
        EVP_PKEY_CTX_set_rsa_pss_saltlen( pkey_ctx, RSA_PSS_SALTLEN_DIGEST);
    }
    bool res = (EVP_DigestVerify( md_ctx, signature, signature_size, signed_data, signed_data_size ) == 1);
    EVP_MD_CTX_free( md_ctx );

    return res;
}

bool TlsHandshake::handshake_certificate_verify_do_verify_signature(
        record::SignatureScheme signature_scheme
        , const uint8_t* signature, uint32_t signature_size, bool from_server )
{
    uint8_t  signed_data[64+sizeof("TLS 1.3, server CertificateVerify")+EVP_MAX_MD_SIZE];
    uint32_t signed_data_size = handshake_certificate_verify_create_signed_data( signed_data, from_server );

    bool signature_verified = false;
    switch( signature_scheme.num() )
    {
        /* ECDSA algorithms */
        case record::SIGNATURES_SCHEME_ECDSA_SECP256R1_SHA256.num():
            signature_verified = handshake_check_signed_data(
                    signature, signature_size, signed_data, signed_data_size
                    , NID_X9_62_id_ecPublicKey, EVP_sha256() );
            break;
        case record::SIGNATURES_SCHEME_ECDSA_SECP384R1_SHA384.num():
            signature_verified = handshake_check_signed_data(
                    signature, signature_size, signed_data, signed_data_size
                    , NID_X9_62_id_ecPublicKey, EVP_sha384() );
            break;
        case record::SIGNATURES_SCHEME_ECDSA_SECP521R1_SHA512.num():
            signature_verified = handshake_check_signed_data(
                    signature, signature_size, signed_data, signed_data_size
                    , NID_X9_62_id_ecPublicKey, EVP_sha512() );
            break;
        /* RSASSA-PSS algorithms with public key OID rsaEncryption */
        case record::SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256.num():
            signature_verified = handshake_check_signed_data(
                    signature, signature_size, signed_data, signed_data_size
                    , NID_rsaEncryption, EVP_sha256() );
            break;
        case record::SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA384.num():
            signature_verified = handshake_check_signed_data(
                    signature, signature_size, signed_data, signed_data_size
                    , NID_rsaEncryption, EVP_sha384() );
            break;
        case record::SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA512.num():
            signature_verified = handshake_check_signed_data(
                    signature, signature_size, signed_data, signed_data_size
                    , NID_rsaEncryption, EVP_sha512() );
            break;
        /* EdDSA algorithms */
        case record::SIGNATURE_SCHEME_ED25519.num():
            signature_verified = handshake_check_signed_data(
                    signature, signature_size, signed_data, signed_data_size, NID_ED25519 );
            break;
        case record::SIGNATURE_SCHEME_ED448.num():
            signature_verified = handshake_check_signed_data(
                    signature, signature_size, signed_data, signed_data_size, NID_ED448 );
            break;
        /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
        case record::SIGNATURE_SCHEME_RSA_PSS_PSS_SHA256.num():
            signature_verified = handshake_check_signed_data(
                    signature, signature_size, signed_data, signed_data_size
                    , NID_rsaEncryption, EVP_sha256() );
            break;
        case record::SIGNATURE_SCHEME_RSA_PSS_PSS_SHA384.num():
            signature_verified = handshake_check_signed_data(
                    signature, signature_size, signed_data, signed_data_size
                    , NID_rsaEncryption, EVP_sha384() );
            break;
        case record::SIGNATURE_SCHEME_RSA_PSS_PSS_SHA512.num():
            signature_verified = handshake_check_signed_data(
                    signature, signature_size, signed_data, signed_data_size
                    , NID_rsaEncryption, EVP_sha512() );
            break;
        default:
            signature_verified = false;
            break;
    }

    if( !signature_verified )
        ERR_print_errors_fp( stderr );

    return signature_verified;
}

uint32_t TlsHandshake::handshake_certificate_verify_create_signature(
        uint8_t* signature, uint32_t signature_size, bool from_server )
{
    uint8_t  signed_data[64+sizeof("TLS 1.3, server CertificateVerify")+EVP_MAX_MD_SIZE];
    uint32_t signed_data_size = handshake_certificate_verify_create_signed_data( signed_data, from_server );

    switch( cert_signature_scheme.num() )
    {
        // ECDSA algorithms
        case record::SIGNATURES_SCHEME_ECDSA_SECP256R1_SHA256.num():
            return handshake_certificate_verify_sign_data(
                    signature, signature_size, signed_data, signed_data_size
                    ,domain_keys->key, NID_X9_62_id_ecPublicKey, EVP_sha256() );
        case record::SIGNATURES_SCHEME_ECDSA_SECP384R1_SHA384.num():
            return handshake_certificate_verify_sign_data(
                    signature, signature_size, signed_data, signed_data_size
                    ,domain_keys->key, NID_X9_62_id_ecPublicKey, EVP_sha384() );
        case record::SIGNATURES_SCHEME_ECDSA_SECP521R1_SHA512.num():
            return handshake_certificate_verify_sign_data(
                    signature, signature_size, signed_data, signed_data_size
                    ,domain_keys->key, NID_X9_62_id_ecPublicKey, EVP_sha512() );
        // RSASSA-PSS algorithms with public key OID rsaEncryption
        case record::SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256.num():
            return handshake_certificate_verify_sign_data(
                    signature, signature_size, signed_data, signed_data_size
                    ,domain_keys->key, NID_rsaEncryption, EVP_sha256() );
        case record::SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA384.num():
            return handshake_certificate_verify_sign_data(
                    signature, signature_size, signed_data, signed_data_size
                    ,domain_keys->key, NID_rsaEncryption, EVP_sha384() );
        case record::SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA512.num():
            return handshake_certificate_verify_sign_data(
                    signature, signature_size, signed_data, signed_data_size
                    ,domain_keys->key, NID_rsaEncryption, EVP_sha512() );
        // EdDSA algorithms
        case record::SIGNATURE_SCHEME_ED25519.num():
            return handshake_certificate_verify_sign_data(
                    signature, signature_size, signed_data, signed_data_size,domain_keys->key, NID_ED25519 );
        case record::SIGNATURE_SCHEME_ED448.num():
            return handshake_certificate_verify_sign_data(
                    signature, signature_size, signed_data, signed_data_size,domain_keys->key, NID_ED448 );
        // RSASSA-PSS algorithms with public key OID RSASSA-PSS
        case record::SIGNATURE_SCHEME_RSA_PSS_PSS_SHA256.num():
            return handshake_certificate_verify_sign_data(
                    signature, signature_size, signed_data, signed_data_size
                    ,domain_keys->key, NID_rsaEncryption, EVP_sha256() );
        case record::SIGNATURE_SCHEME_RSA_PSS_PSS_SHA384.num():
            return handshake_certificate_verify_sign_data(
                    signature, signature_size, signed_data, signed_data_size
                    ,domain_keys->key, NID_rsaEncryption, EVP_sha384() );
        case record::SIGNATURE_SCHEME_RSA_PSS_PSS_SHA512.num():
            return handshake_certificate_verify_sign_data(
                    signature, signature_size, signed_data, signed_data_size
                    ,domain_keys->key, NID_rsaEncryption, EVP_sha512() );
        default:
            return 0;
    }
}

void TlsHandshake::handshake_set_certificate( X509* cert )
{
    m_certificate = cert;
}

}
