/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once

#include <libcornet/tls/parser.hpp>
#include <libcornet/tls/tls_read_buffer.hpp>
#include <libcornet/tls/record_layer.hpp>
#include <libcornet/tls/key_store.hpp>
#include <libcornet/tls/crypto/record_cryptor.hpp>

#include <libcornet/coroutines_utils.hpp>

namespace pioneer19::cornet::tls13
{

/**
 * @brief helper functions to process tls handshake on server side
 */
template< typename OS_SEAM >
class TlsAcceptorImpl
{
public:
    TlsAcceptorImpl() = delete;
    TlsAcceptorImpl( const TlsAcceptorImpl& ) = delete;
    TlsAcceptorImpl( TlsAcceptorImpl&& ) = delete;
    TlsAcceptorImpl& operator=( TlsAcceptorImpl&& ) = delete;
    TlsAcceptorImpl& operator=( const TlsAcceptorImpl& ) = delete;
    ~TlsAcceptorImpl() = default;

    static coroutines::CoroutineAwaiter<bool> read_client_hello_record(
            RecordLayer& record_layer, crypto::TlsHandshake& tls_handshake,
            record::Parser& parser, KeyStore* domain_keys_store );
    static coroutines::CoroutineAwaiter<bool> read_client_finished_record(
            RecordLayer& record_layer, crypto::TlsHandshake& tls_handshake, record::Parser& parser );

    static uint32_t produce_server_hello_record(
            TlsReadBuffer& buffer, crypto::TlsHandshake& tls_handshake );
    static uint32_t produce_encrypted_extensions_record(
            TlsReadBuffer& buffer, crypto::TlsHandshake& tls_handshake );
    static uint32_t produce_certificate_record(
            TlsReadBuffer& buffer, crypto::TlsHandshake& tls_handshake );
    static uint32_t produce_certificate_verify_record(
            TlsReadBuffer& buffer, crypto::TlsHandshake& tls_handshake );
    static uint32_t produce_server_finished_record(
            TlsReadBuffer& buffer, crypto::TlsHandshake& tls_handshake );
};

}
