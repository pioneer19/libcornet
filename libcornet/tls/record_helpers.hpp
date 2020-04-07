/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once

#include <cstdint>

#include <libcornet/tls/crypto/record_cryptor.hpp>

namespace pioneer19::cornet::tls13
{

class RecordLayer;

/**
 * @brief helpers to create tls network records
 */
struct RecordHelpers
{
    static uint32_t client_hello_record_buffer_size( crypto::TlsHandshake& record_cryptor );
    static uint32_t create_client_hello_record( crypto::TlsHandshake& record_cryptor, uint8_t* buffer );
    static uint32_t client_finished_record_buffer_size( crypto::TlsHandshake& record_cryptor );
    static uint32_t create_client_finished_record( crypto::TlsHandshake& record_cryptor, uint8_t* buffer );
    static uint32_t server_hello_record_buffer_size( crypto::TlsHandshake& );
    static uint32_t create_server_hello_record( crypto::TlsHandshake& record_cryptor, uint8_t* buffer );
    static uint32_t create_encrypted_extensions_record( crypto::TlsHandshake&, uint8_t* buffer );
    static uint32_t create_certificate_record( crypto::TlsHandshake&, uint8_t* buffer );
    static uint32_t create_certificate_verify_record( crypto::TlsHandshake&, uint8_t* buffer );
    static uint32_t create_server_finished_record( crypto::TlsHandshake&, uint8_t* buffer );
};

}
