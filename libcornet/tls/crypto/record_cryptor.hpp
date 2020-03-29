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

#include <libcornet/tls/crypto/record_ciphers.hpp>

namespace pioneer19::cornet::tls13::crypto
{

class TlsHandshake;

class RecordCryptor
{
public:
    RecordCryptor() = default;
    ~RecordCryptor() noexcept;
    RecordCryptor( RecordCryptor&& ) noexcept;
    RecordCryptor& operator=( RecordCryptor&& ) noexcept;

    uint32_t decrypt_record( const uint8_t* record, uint8_t* out_buffer ) noexcept;
    uint32_t encrypt_record( uint8_t* record, const uint8_t* data, uint32_t data_size ) noexcept;
    [[nodiscard]]
    uint32_t digest_size() const noexcept { return m_tls_cipher_suite.digest_size(); }

    void set_application_traffic_secrets( TlsHandshake& tls_handshake
            , const uint8_t* server_finished_transcript_hash
            , const uint8_t* client_finished_transcript_hash
            , bool sender_is_server ) noexcept;

    RecordCryptor( const RecordCryptor& ) = delete;
    RecordCryptor& operator=( const RecordCryptor& ) = delete;

private:
    friend class TlsHandshake;

    TlsCipherSuite m_tls_cipher_suite;
    uint8_t* m_client_application_traffic_secret = nullptr;
    uint8_t* m_server_application_traffic_secret = nullptr;
    uint8_t* m_exporter_master_secret   = nullptr;
    uint8_t* m_resumption_master_secret = nullptr;
    void allocate_secrets();
    void move_data( RecordCryptor& other );
};

}
