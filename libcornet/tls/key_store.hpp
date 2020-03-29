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

#pragma once

#include <cstdint>

#include <array>
#include <string>

#include <openssl/x509.h>

#include <libcornet/tls/types.hpp>

namespace pioneer19::cornet::tls13
{

struct CertificateSignatureSchemes
{
    uint16_t count = 0;
    std::array<record::SignatureScheme,3> schemes= {
            record::SIGNATURE_SCHEME_PRIVATE
            , record::SIGNATURE_SCHEME_PRIVATE
            , record::SIGNATURE_SCHEME_PRIVATE };
};

struct DomainKeys
{
    EVP_PKEY* key  = nullptr;
    X509*     domain_cert = nullptr;
    X509*     cert_chain  = nullptr;
    uint32_t  der_cert_size  = 0;
    uint32_t  der_chain_size = 0;
    uint8_t*  der_domain_cert = nullptr;
    uint8_t*  der_cert_chain  = nullptr;
    CertificateSignatureSchemes signature_schemes;
};

class KeyStore
{
public:
    KeyStore() = default;
    virtual ~KeyStore() = default;

    virtual DomainKeys* find( const char* domain_name ) noexcept = 0;

    KeyStore( KeyStore&& )            = delete;
    KeyStore& operator=( KeyStore&& ) = delete;
    KeyStore( const KeyStore& )       = delete;
    KeyStore& operator=( const KeyStore& ) = delete;

    static CertificateSignatureSchemes signature_scheme_for_cert( X509* cert );
    static bool is_supported_signature_scheme( record::SignatureScheme signature_scheme );
    static record::SignatureScheme find_best_signature_scheme(
            record::SignatureScheme*, uint32_t schemes_count, CertificateSignatureSchemes& );
};

class SingleDomainKeyStore : public KeyStore
{
public:
    SingleDomainKeyStore( const char* domain_name, const char* key_file
            , const char* cert_file, const char* cert_chain = nullptr );
    ~SingleDomainKeyStore() override;

    DomainKeys* find( const char* domain_name ) noexcept final;

    SingleDomainKeyStore() = delete;
    SingleDomainKeyStore( SingleDomainKeyStore&& )            = delete;
    SingleDomainKeyStore& operator=( SingleDomainKeyStore&& ) = delete;
    SingleDomainKeyStore( const SingleDomainKeyStore& )       = delete;
    SingleDomainKeyStore& operator=( const SingleDomainKeyStore& ) = delete;

private:
    std::string m_domain_name;
    DomainKeys  m_keys;
};

}
