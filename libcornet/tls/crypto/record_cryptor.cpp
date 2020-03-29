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
#include <libcornet/tls/crypto/record_cryptor.hpp>

#include <utility>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <libcornet/tls/crypto/hkdf.hpp>
#include <libcornet/tls/crypto/tls_handshake.hpp>

namespace pioneer19::cornet::tls13::crypto
{

RecordCryptor::~RecordCryptor() noexcept
{
    delete [] m_client_application_traffic_secret;
}

RecordCryptor::RecordCryptor( RecordCryptor&& other ) noexcept
{
    move_data( other );
    other.m_client_application_traffic_secret = nullptr;
}

RecordCryptor& RecordCryptor::operator=( RecordCryptor&& other ) noexcept
{
    if( &other != this )
    {
        delete [] m_client_application_traffic_secret;
        move_data( other );
        other.m_client_application_traffic_secret = nullptr;
    }
    return *this ;
}

void RecordCryptor::move_data( RecordCryptor& other )
{
    m_tls_cipher_suite = std::move(other.m_tls_cipher_suite);
    m_client_application_traffic_secret = other.m_client_application_traffic_secret;
    m_server_application_traffic_secret = other.m_server_application_traffic_secret;
    m_exporter_master_secret            = other.m_exporter_master_secret;
    m_resumption_master_secret          = other.m_resumption_master_secret;
}
void RecordCryptor::allocate_secrets()
{
    auto hash_size = m_tls_cipher_suite.digest_size();
    auto* m_data = new uint8_t[ 4 * hash_size ];

    m_client_application_traffic_secret = m_data;
    m_server_application_traffic_secret = m_data + hash_size;
    m_exporter_master_secret   = m_data + 2*hash_size;
    m_resumption_master_secret = m_data + 3*hash_size;
}

void RecordCryptor::set_application_traffic_secrets( TlsHandshake& tls_handshake
        , const uint8_t* server_finished_transcript_hash
        , const uint8_t* client_finished_transcript_hash
        , bool sender_is_server ) noexcept
{
    allocate_secrets();

    // Derive-Secret(Handshake Secret, "derived", "") -> Master Secret salt
    uint8_t master_secret_salt[ EVP_MAX_MD_SIZE ];
    const uint8_t derived_label[] = "derived";
    uint8_t zeros_size_of_hash_len[ EVP_MAX_MD_SIZE ] = { 0 };
    uint8_t* master_secret = master_secret_salt;

    derive_secret( m_tls_cipher_suite.digest()
                   ,tls_handshake.m_handshake_secret, m_tls_cipher_suite.digest_size()
                   ,derived_label, sizeof(derived_label)-1, nullptr, 0
                   ,master_secret_salt );
    // 0(hash.size) -> HKDF-Extract = Master Secret
    hkdf_extract( m_tls_cipher_suite.digest()
                  ,master_secret_salt, m_tls_cipher_suite.digest_size()
                  ,zeros_size_of_hash_len, m_tls_cipher_suite.digest_size()
                  , master_secret );
    /*
     * Derive-Secret(., "c ap traffic",ClientHello...server Finished)
     *               = client_application_traffic_secret_0
     * Derive-Secret(., "s ap traffic", ClientHello...server Finished)
     *               = server_application_traffic_secret_0
     * Derive-Secret(., "exp master", ClientHello...server Finished)
     *               = exporter_master_secret
     * Derive-Secret(., "res master", ClientHello...client Finished)
     *               = resumption_master_secret
     *
     * Derive-Secret(Secret, Label, Messages) =
     *          HKDF-Expand-Label(Secret, Label,
     *                            Transcript-Hash(Messages), Hash.length)
     */
    const uint8_t c_ap_traffic_label[] = "c ap traffic";
    hkdf_expand_label( m_tls_cipher_suite.digest()
                       ,master_secret, m_tls_cipher_suite.digest_size()
                       ,c_ap_traffic_label, sizeof(c_ap_traffic_label) - 1
                       ,server_finished_transcript_hash, m_tls_cipher_suite.digest_size()
                       ,m_client_application_traffic_secret
                       ,m_tls_cipher_suite.digest_size() );
    /*
     * Derive-Secret(., "s ap traffic", ClientHello...server Finished)
     *               = server_application_traffic_secret_0
     */
    const uint8_t s_ap_traffic_label[] = "s ap traffic";
    hkdf_expand_label( m_tls_cipher_suite.digest()
                       ,master_secret, m_tls_cipher_suite.digest_size()
                       ,s_ap_traffic_label, sizeof(s_ap_traffic_label) - 1
                       ,server_finished_transcript_hash, m_tls_cipher_suite.digest_size()
                       ,m_server_application_traffic_secret
                       ,m_tls_cipher_suite.digest_size() );
    /*
     * Derive-Secret(., "exp master", ClientHello...server Finished)
     *               = exporter_master_secret
     */
    const uint8_t exp_master_label[] = "exp master";
    hkdf_expand_label( m_tls_cipher_suite.digest()
                       ,master_secret, m_tls_cipher_suite.digest_size()
                       ,exp_master_label, sizeof(exp_master_label) - 1
                       ,server_finished_transcript_hash, m_tls_cipher_suite.digest_size()
                       ,m_exporter_master_secret
                       ,m_tls_cipher_suite.digest_size() );
    /*
     * Derive-Secret(., "res master", ClientHello...client Finished)
     *               = resumption_master_secret
     */
    const uint8_t res_master_label[] = "res master";
    hkdf_expand_label( m_tls_cipher_suite.digest()
                       ,master_secret, m_tls_cipher_suite.digest_size()
                       ,res_master_label, sizeof(res_master_label) - 1
                       ,client_finished_transcript_hash, m_tls_cipher_suite.digest_size()
                       ,m_resumption_master_secret
                       ,m_tls_cipher_suite.digest_size() );

    /*
     * [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
     * [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)
     */
    uint8_t* sender_secret   = m_client_application_traffic_secret;
    uint8_t* receiver_secret = m_server_application_traffic_secret;
    if( sender_is_server )
    {
        sender_secret   = m_server_application_traffic_secret;
        receiver_secret = m_client_application_traffic_secret;
    }
    const uint8_t key_label[] = "key";
    const uint8_t iv_label[]  = "iv";
    // sender key and iv
    hkdf_expand_label( m_tls_cipher_suite.digest()
                       ,sender_secret,m_tls_cipher_suite.digest_size()
                       ,key_label, sizeof(key_label)-1, nullptr, 0
                       ,m_tls_cipher_suite.sender_key_data(), m_tls_cipher_suite.key_size() );
    hkdf_expand_label( m_tls_cipher_suite.digest()
                       ,sender_secret,m_tls_cipher_suite.digest_size()
                       ,iv_label, sizeof(iv_label)-1, nullptr, 0
                       ,m_tls_cipher_suite.sender_iv_data(), m_tls_cipher_suite.iv_size() );
    // receiver key and iv
    hkdf_expand_label( m_tls_cipher_suite.digest()
                       ,receiver_secret,m_tls_cipher_suite.digest_size()
                       ,key_label, sizeof(key_label)-1, nullptr, 0
                       ,m_tls_cipher_suite.receiver_key_data(), m_tls_cipher_suite.key_size() );
    hkdf_expand_label( m_tls_cipher_suite.digest()
                       ,receiver_secret,m_tls_cipher_suite.digest_size()
                       ,iv_label, sizeof(iv_label)-1, nullptr, 0
                       ,m_tls_cipher_suite.receiver_iv_data(), m_tls_cipher_suite.iv_size() );
    m_tls_cipher_suite.reset_key_counters();
}

uint32_t RecordCryptor::decrypt_record( const uint8_t* record, uint8_t* out_buffer ) noexcept
{
    auto* encrypted_record = reinterpret_cast<const record::TLSCiphertext*>(record);
    uint16_t encrypted_data_size = encrypted_record->length();

    auto* encrypted_data = record + sizeof(record::TLSCiphertext);
    const uint8_t* tag = encrypted_data + encrypted_data_size - m_tls_cipher_suite.tag_size();

    return m_tls_cipher_suite.decrypt(
            encrypted_data, encrypted_data_size - m_tls_cipher_suite.tag_size()
            ,record, sizeof(record::TLSCiphertext), tag,
            out_buffer );
}

uint32_t RecordCryptor::encrypt_record( uint8_t* record, const uint8_t* data, uint32_t data_size ) noexcept
{
    /*
     * struct {
     *     opaque content[TLSPlaintext.length];
     *     ContentType type;
     *     uint8 zeros[length_of_padding];
     * } TLSInnerPlaintext;
     */
    auto* tls_ciphertext_record = reinterpret_cast<record::TLSCiphertext*>( record );

    auto* encrypted_data = record + sizeof(record::TLSCiphertext);
    auto* inner_content_type = encrypted_data + data_size;
    *inner_content_type = static_cast<uint8_t>(tls_ciphertext_record->opaque_type);
    uint32_t tail_size  = sizeof(record::ContentType); // without tag size

    tls_ciphertext_record->init();
    tls_ciphertext_record->finalize( data_size + tail_size + m_tls_cipher_suite.tag_size() );

    uint8_t* tag = encrypted_data + data_size + tail_size;

    auto res = m_tls_cipher_suite.encrypt2( data, data_size,
            encrypted_data + data_size, tail_size
            ,record, sizeof(record::TLSCiphertext)
            ,encrypted_data, tag );

    return sizeof(record::TLSCiphertext) + res + m_tls_cipher_suite.tag_size();
}

}
