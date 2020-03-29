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
