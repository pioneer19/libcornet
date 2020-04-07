/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
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
