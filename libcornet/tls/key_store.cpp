/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <cstdio>
#include <cassert>
#include <system_error>

#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

#include <libcornet/tls/key_store.hpp>
#include <libcornet/guards.hpp>

namespace pioneer19::cornet::tls13
{

static X509* load_cert( const char* cert_file_name )
{
    FILE* cert_file = fopen( cert_file_name, "r" );
    if( cert_file == nullptr )
        throw std::system_error( errno, std::system_category(),
                std::string("fopen() cert file \"")+cert_file_name );
    auto file_close_guard = guards::make_scope_guard( [cert_file](){ fclose(cert_file); } );

    X509* cert = PEM_read_X509(cert_file, nullptr, nullptr, nullptr );
    if( cert == nullptr )
    {
        char err_buffer[1024];
        std::string err_string{ ERR_error_string( ERR_get_error(), err_buffer ) };
        throw std::runtime_error( "PEM_read_X509 failed" + err_string );
    }

    return cert;
}
static EVP_PKEY* load_key( const char* key_file_name )
{
    FILE* key_file = fopen( key_file_name, "r" );
    if( key_file == nullptr )
        throw std::system_error( errno, std::system_category(),
                std::string("fopen() key file \"")+key_file_name );
    auto file_close_guard = guards::make_scope_guard( [key_file](){ fclose(key_file); } );


    EVP_PKEY* pkey = PEM_read_PrivateKey( key_file, nullptr, nullptr, nullptr );
    if( pkey == nullptr )
    {
        char err_buffer[1024];
        std::string err_string{ ERR_error_string( ERR_get_error(), err_buffer ) };
        throw std::runtime_error( "PEM_read_PrivateKey failed" + err_string );
    }

    return pkey;
}

static const char* subject_common_name( const X509 *server_cert )
{
    // Find the position of the CN field in the Subject field of the certificate
    int common_name_loc = X509_NAME_get_index_by_NID(
            X509_get_subject_name( (X509*)server_cert ), NID_commonName, -1 );
    if (common_name_loc < 0)
        return nullptr;

    // Extract the CN field
    X509_NAME_ENTRY* common_name_entry = X509_NAME_get_entry(
            X509_get_subject_name((X509 *) server_cert), common_name_loc );
    if( common_name_entry == nullptr )
        return nullptr;

    // Convert the CN field to a C string
    ASN1_STRING* common_name_asn1 = X509_NAME_ENTRY_get_data( common_name_entry );
    if (common_name_asn1 == NULL)
        return nullptr;
    const char* common_name_str = (const char *)ASN1_STRING_get0_data( common_name_asn1 );

    if( strlen(common_name_str) == 0 )
        return nullptr;

    return common_name_str;
}

static const char* subject_alternative_name( const X509 *server_cert )
{
    // Try to extract the names within the SAN extension from the certificate
    STACK_OF(GENERAL_NAME)* san_names = static_cast<stack_st_GENERAL_NAME*>(X509_get_ext_d2i(
            (X509*)server_cert, NID_subject_alt_name, nullptr, nullptr ) );
    if( san_names == nullptr )
        return nullptr;
    int san_names_count = sk_GENERAL_NAME_num( san_names);

    // Check each name within the extension
    for( int i=0; i < san_names_count; ++i )
    {
        const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, i);
        if( current_name->type == GEN_DNS )
        {
            // Current name is a DNS name, let's check it
            const char* dns_name = (const char *)ASN1_STRING_get0_data( current_name->d.dNSName );

            // Make sure there isn't an embedded NUL character in the DNS name
            if( strlen(dns_name) != 0 )
                printf( "alt name \"%s\"\n", dns_name );
        }
    }
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

    return nullptr;
}

SingleDomainKeyStore::SingleDomainKeyStore(
        const char* domain_name, const char* key_file, const char* cert_file, const char* cert_chain )
        :m_domain_name{domain_name}
{
    assert( domain_name != nullptr );
    assert( key_file    != nullptr );
    assert( cert_file   != nullptr );

    m_keys.key = load_key( key_file );
    if( m_keys.key != nullptr )
        printf( "key loaded\n" );

    m_keys.domain_cert = load_cert( cert_file );
    int res = i2d_X509( m_keys.domain_cert, &m_keys.der_domain_cert );
    if( res < 0 )
    {
        char err_buffer[1024];
        std::string err_string{ ERR_error_string( ERR_get_error(), err_buffer ) };
        throw std::runtime_error( "i2d_X509 for cert failed" + err_string );
    }
    m_keys.der_cert_size = res;
    m_keys.signature_schemes = signature_scheme_for_cert( m_keys.domain_cert );

    printf( "loaded cert subject CN \"%s\"\n", subject_common_name( m_keys.domain_cert) );
    subject_alternative_name( m_keys.domain_cert );

    if( cert_chain != nullptr )
    {
        m_keys.cert_chain = load_cert( cert_chain );
        res = i2d_X509( m_keys.cert_chain, &m_keys.der_cert_chain );
        if( res < 0 )
        {
            char err_buffer[1024];
            std::string err_string{ERR_error_string( ERR_get_error(), err_buffer )};
            throw std::runtime_error( "i2d_X509 for cert chain failed" + err_string );
        }
        m_keys.der_chain_size = res;

        printf( "loaded cert chain subject CN \"%s\"\n", subject_common_name( m_keys.cert_chain ));
        subject_alternative_name( m_keys.cert_chain );
    }
}

SingleDomainKeyStore::~SingleDomainKeyStore()
{
    OPENSSL_free( m_keys.der_domain_cert );
    OPENSSL_free( m_keys.der_cert_chain );
    if( m_keys.key != nullptr )
        EVP_PKEY_free( m_keys.key );
    if( m_keys.cert_chain != nullptr )
        X509_free( m_keys.cert_chain );
    if( m_keys.domain_cert != nullptr )
        X509_free( m_keys.domain_cert );
}


DomainKeys* SingleDomainKeyStore::find( const char* domain_name ) noexcept
{
    if( domain_name == m_domain_name )
        return &m_keys;

    return nullptr;
}

CertificateSignatureSchemes KeyStore::signature_scheme_for_cert( X509* cert )
{
    assert( cert != nullptr );

    EVP_PKEY* pkey = X509_get0_pubkey( cert );
    if( pkey == nullptr )
    {
        char err_buffer[1024];
        std::string err_string{ ERR_error_string( ERR_get_error(), err_buffer ) };
        throw std::runtime_error( "signature_scheme_for_cert failed" + err_string );
    }
    auto nid = EVP_PKEY_id( pkey );
    switch( nid )
    {
        case NID_rsaEncryption:
            return { 3, { record::SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256
                          , record::SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA384
                          , record::SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA512 } };
        case NID_rsassaPss:
            return { 3, { record::SIGNATURE_SCHEME_RSA_PSS_PSS_SHA256
                          , record::SIGNATURE_SCHEME_RSA_PSS_PSS_SHA384
                          , record::SIGNATURE_SCHEME_RSA_PSS_PSS_SHA512 } };
        case NID_X9_62_id_ecPublicKey:
            return { 3, { record::SIGNATURES_SCHEME_ECDSA_SECP256R1_SHA256
                     , record::SIGNATURES_SCHEME_ECDSA_SECP384R1_SHA384
                     , record::SIGNATURES_SCHEME_ECDSA_SECP521R1_SHA512 } };
        case NID_ED25519:
            return { 1, { record::SIGNATURE_SCHEME_ED25519 } };
        case NID_ED448:
            return { 1, { record::SIGNATURE_SCHEME_ED448 } };
        default:
            throw std::runtime_error( "signature_scheme_for_cert() unsupported NID " + std::to_string(nid) );
    }
}

bool KeyStore::is_supported_signature_scheme( record::SignatureScheme signature_scheme )
{
    switch( signature_scheme.num() )
    {
        case record::SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256.num():
        case record::SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA384.num():
        case record::SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA512.num():

        case record::SIGNATURE_SCHEME_RSA_PSS_PSS_SHA256.num():
        case record::SIGNATURE_SCHEME_RSA_PSS_PSS_SHA384.num():
        case record::SIGNATURE_SCHEME_RSA_PSS_PSS_SHA512.num():

        case record::SIGNATURES_SCHEME_ECDSA_SECP256R1_SHA256.num():
        case record::SIGNATURES_SCHEME_ECDSA_SECP384R1_SHA384.num():
        case record::SIGNATURES_SCHEME_ECDSA_SECP521R1_SHA512.num():

        case record::SIGNATURE_SCHEME_ED25519.num():
        case record::SIGNATURE_SCHEME_ED448.num():
            return true;
        default:
            return false;
    }
}

static bool is_in_certificate_signature_schemes(
        CertificateSignatureSchemes& cert_schemes, record::SignatureScheme signature_scheme )
{
    for( uint32_t i = 0; i < cert_schemes.count; ++i )
    {
        if( cert_schemes.schemes[i] == signature_scheme )
            return true;
    }
    return false;
}
record::SignatureScheme KeyStore::find_best_signature_scheme(
        record::SignatureScheme* schemes, uint32_t schemes_count
        , CertificateSignatureSchemes& certificate_schemes )
{
    for( uint32_t i = 0; i < schemes_count; ++i )
    {
        if( is_in_certificate_signature_schemes( certificate_schemes, schemes[i] ) )
        {
            return schemes[i];
        }
    }

    return record::SIGNATURE_SCHEME_PRIVATE;
}

}
