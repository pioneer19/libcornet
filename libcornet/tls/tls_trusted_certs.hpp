/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once
#include <openssl/err.h>
#include <openssl/x509.h>

namespace pioneer19::cornet::tls13
{

class TlsTrustedCerts
{
public:
    TlsTrustedCerts();
    ~TlsTrustedCerts() noexcept;

    TlsTrustedCerts( TlsTrustedCerts&& ) = delete;
    TlsTrustedCerts& operator=( TlsTrustedCerts&& ) = delete;

    TlsTrustedCerts( const TlsTrustedCerts& ) = delete;
    TlsTrustedCerts& operator=( const TlsTrustedCerts& ) = delete;

    static X509_STORE* store_instance();

private:
    X509_STORE* store() noexcept
    { return m_store; }

    X509_STORE* m_store = nullptr;
};

inline TlsTrustedCerts::TlsTrustedCerts()
{
    m_store = X509_STORE_new();
    if( m_store == nullptr )
        throw std::runtime_error( "TlsTrustedCerts::TlsTrustedCerts() failed create empty store" );

    if( !X509_STORE_set_default_paths( m_store ))
    {
        X509_STORE_free( m_store );
        throw std::runtime_error( "TlsTrustedCerts::TlsTrustedCerts() failed load default paths" );
    }
    ERR_clear_error();
}

inline TlsTrustedCerts::~TlsTrustedCerts() noexcept
{
    if( m_store )
        X509_STORE_free( m_store );
}

inline X509_STORE* TlsTrustedCerts::store_instance()
{
    static thread_local TlsTrustedCerts trusted_tls_certs;

    return trusted_tls_certs.store();
}

}
