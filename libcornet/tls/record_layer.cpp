/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <deque>
#include <utility>
#include <iterator>
#include <algorithm>
#include <stdexcept>

#include <openssl/x509.h>

#include <libcornet/tls/crypto/record_cryptor.hpp>
#include <libcornet/tls/crypto/tls_handshake.hpp>
#include <libcornet/tls/record_layer.hpp>
#include <libcornet/tls/parser.hpp>
#include <libcornet/tls/tls_read_buffer.hpp>
#include <libcornet/tls/tls_connector.hpp>
#include <libcornet/tls/crypto/hkdf.hpp>
#include <libcornet/tls/types.hpp>

#include <libcornet/cache_allocator.hpp>

#include <iostream>

namespace pioneer19::cornet::tls13
{

static bool is_full_record_in_buffer( const uint8_t* buffer, uint32_t buffer_size )
{
    if( sizeof(record::TLSCiphertext) > buffer_size )
        return false;
    const auto* tls_record = reinterpret_cast<const record::TLSCiphertext*>( buffer );
    return buffer_size >= ( tls_record->length() + sizeof(record::TLSCiphertext) );
}

uint16_t RecordLayer::decrypt_record( uint8_t* buffer, crypto::RecordCryptor& cryptor )
{
    auto bytes_decrypted = cryptor.decrypt_record(
            buffer, buffer + sizeof( record::TLSCiphertext ) );
    std::cout << "RecordLayer::tls_connect decrypted " << bytes_decrypted << " bytes\n";
    if( bytes_decrypted == 0 )
        std::runtime_error( "RecordLayer::tls_connect failed decrypt record" );
    /*
         * struct {
         *     opaque content[TLSPlaintext.length];
         *     ContentType type;
         *     uint8 zeros[length_of_padding];
         * } TLSInnerPlaintext;
         */
    // decrypted data will contain TLSInnerPlaintext, so I need skip zeroes on tail
    // and found record ContentType, then calculate length
    auto* tls_record = reinterpret_cast<record::TlsPlaintext*>( buffer );
    auto it = std::find_if(
            std::reverse_iterator( buffer + sizeof( record::TlsPlaintext ) + bytes_decrypted )
            , std::reverse_iterator( buffer + sizeof( record::TlsPlaintext ))
            , []( uint8_t value ){ return value != 0; } );
    tls_record->init( static_cast<record::ContentType>(*it));
    tls_record->finalize( std::reverse_iterator( buffer + sizeof( record::TlsPlaintext ))
                          - it - sizeof( record::ContentType ));

    return bytes_decrypted;
}

coroutines::CoroutineAwaiter<void> RecordLayer::read_full_record()
{
    if( !is_full_record_in_buffer( m_read_buffer.head(), m_read_buffer.size() ) )
    {
        m_read_buffer.compact();
        while( true )
        {
            auto read_bytes = co_await m_socket.async_read(
                    m_read_buffer.tail(), m_read_buffer.tail_size() );
            if( read_bytes == 0 )
                throw std::runtime_error( "RecordLayer::read_full_record() failed async_read" );
            m_read_buffer.produce( read_bytes );

            if( is_full_record_in_buffer( m_read_buffer.head(), m_read_buffer.size() ) )
                break;
            else
            {
                if( m_read_buffer.tail_size() > 0 )
                    continue;
                else
                    throw std::runtime_error( "RecordLayer::read_full_record() record do not fit in buffer" );
            }
        }
    }
}

coroutines::CoroutineAwaiter<void> RecordLayer::read_full_record_skip_change_cipher_spec()
{
    while( true )
    {
        co_await read_full_record();
        auto encrypted_record_size = record::full_record_size( m_read_buffer.head() );
        if( record::record_content_type( m_read_buffer.head() )
            == record::ContentType::CHANGE_CIPHER_SPEC )
        {
            m_read_buffer.consume( encrypted_record_size );
        }
        else
            break;
    }
}

coroutines::CoroutineAwaiter<uint32_t> RecordLayer::async_read(
        void* user_buffer, uint32_t buffer_size, uint32_t min_threshold )
{
    uint32_t bytes_copied = 0;
    // conserved data will contain previously decrypted but not fully read data
    if( m_read_buffer.conserved_size() > 0 )
    {
        if( m_read_buffer.conserved_size() > buffer_size )
        {
            std::copy_n( m_read_buffer.conserved_data(), buffer_size, (uint8_t*)user_buffer );
            m_read_buffer.consume_conserved( buffer_size );
            co_return buffer_size;
        } else {
            bytes_copied = m_read_buffer.conserved_size();
            std::copy_n( m_read_buffer.conserved_data(),
                    m_read_buffer.conserved_size(), (uint8_t*)user_buffer );
            m_read_buffer.erase_conserved();
        }
    }

    while( bytes_copied < min_threshold )
    {
        auto full_record_size = co_await read_and_decrypt_record();
        std::cout << "RecordLayer::async_read() read_and_decrypt_record() returns "
                  << full_record_size << " bytes\n";

        switch( record::record_content_type( m_read_buffer.head() ) )
        {
            case record::ContentType::CHANGE_CIPHER_SPEC:
                // this must send some Alert
            case record::ContentType::HANDSHAKE:
                // this must process psk tickets
                m_read_buffer.consume( full_record_size );
                break;
            case record::ContentType::APPLICATION_DATA:
            {
                uint32_t content_size = record::record_content_size( m_read_buffer.head() );
                if( content_size > (buffer_size-bytes_copied) )
                {
                    std::copy_n( m_read_buffer.head() + sizeof(record::TlsPlaintext)
                                 , (buffer_size-bytes_copied)
                                 , (uint8_t*)user_buffer+bytes_copied );
                    m_read_buffer.conserve_head( sizeof(record::TlsPlaintext) + (buffer_size-bytes_copied)
                                            ,content_size - (buffer_size-bytes_copied)
                                            ,full_record_size
                                            -(sizeof(record::TlsPlaintext)+content_size) );
                    bytes_copied = buffer_size;
                } else {
                    std::copy_n( m_read_buffer.head() + sizeof(record::TlsPlaintext)
                                 , content_size
                                 , (uint8_t*)user_buffer+bytes_copied );
                    bytes_copied += content_size;
                    m_read_buffer.consume( full_record_size );
                }
                break;
            }
            default:
                throw std::runtime_error( "RecordLayer::async_read unexpected record content type "
                                          + std::to_string( static_cast<uint8_t>(
                                                  record::record_content_type( m_read_buffer.head()))));
        }
    }

    co_return bytes_copied;
}

coroutines::CoroutineAwaiter <uint32_t> RecordLayer::read_and_decrypt_record()
{
    co_await read_full_record();

    record::print_net_record( m_read_buffer.head(), m_read_buffer.size() );
    auto encrypted_record_size = record::full_record_size( m_read_buffer.head() );
    std::cout << "read_and_decrypt_record full record size " << encrypted_record_size << "\n";
    // FIXME: record MUST be encrypted
    if( record::record_content_type( m_read_buffer.head() ) == record::ContentType::APPLICATION_DATA )
    {
        decrypt_record( m_read_buffer.head(), m_cryptor );
        std::cout << "decrypted record\n";
        record::print_net_record( m_read_buffer.head(), m_read_buffer.size() );
    }

    co_return encrypted_record_size;
}

coroutines::CoroutineAwaiter<uint32_t> RecordLayer::read_record_decrypt_and_skip_change_cipher()
{
    uint32_t encrypted_record_size = 0;
    while( true )
    {
        co_await read_full_record_skip_change_cipher_spec();

        record::print_net_record( m_read_buffer.head(), m_read_buffer.size());
        encrypted_record_size = record::full_record_size( m_read_buffer.head());

        printf( "read_record_decrypt_and_skip_change_cipher() enc. record size %u\n", encrypted_record_size );
        if( record::record_content_type( m_read_buffer.head() ) != record::ContentType::APPLICATION_DATA )
        {
            throw std::runtime_error(
                    "RecordLayer::read_record_decrypt_and_skip_change_cipher()"
                    " got unencrypted record content type "
                    + std::to_string( static_cast<uint8_t>(record::record_content_type( m_read_buffer.head()))));
        }

        decrypt_record( m_read_buffer.head(), m_cryptor );
        printf( "decrypted record\n" );
        record::print_net_record( m_read_buffer.head(), m_read_buffer.size());

        if( record::record_content_type( m_read_buffer.head()) == record::ContentType::CHANGE_CIPHER_SPEC )
            m_read_buffer.consume( encrypted_record_size );
        else
            break;
    }

    co_return encrypted_record_size;
}

coroutines::CoroutineAwaiter <uint32_t> RecordLayer::async_write_buffer()
{
    uint32_t bytes_sent = 0;
    while( bytes_sent < m_write_buffer.size() )
    {
        auto res = co_await m_socket.async_write(
                m_write_buffer.head() + bytes_sent, m_write_buffer.size() - bytes_sent );
        if( res > 0 )
            bytes_sent += res;
        else
            break;
    }
    m_write_buffer.consume( bytes_sent );

    co_return bytes_sent;
}
coroutines::CoroutineAwaiter<uint32_t> RecordLayer::encrypt_and_send_record( const void* buffer, uint32_t chunk_size )
{
    uint8_t* record = m_write_buffer.tail();

    auto rec_size = m_cryptor.encrypt_record( record, (const uint8_t*)buffer, chunk_size );
    std::cout << "encrypted record size " << rec_size << "\n";
    record::print_net_record( record, rec_size );
    m_write_buffer.produce( rec_size );

    auto bytes_sent = co_await async_write_buffer();
    assert( bytes_sent == rec_size );

    co_return rec_size;
}

coroutines::CoroutineAwaiter<void> RecordLayer::encrypt_and_send_application_data(
        const void* buffer, uint32_t chunk_size )
{
    assert( chunk_size <= 16 * 1024 ); // TlsPlaintext payload limit
    uint8_t* record = m_write_buffer.tail();

    auto* tls_plaintext_record = reinterpret_cast<record::TlsPlaintext*>( record );
    tls_plaintext_record->init( record::ContentType::APPLICATION_DATA );
    tls_plaintext_record->finalize( chunk_size );

    auto rec_size = co_await encrypt_and_send_record( buffer, chunk_size );
    std::cout << "RecordLayer::async_write wrote " << rec_size << " bytes\n";
}

coroutines::CoroutineAwaiter<void> RecordLayer::async_write( const void* buffer, uint32_t buffer_size )
{
    uint32_t total_sent = 0;
    while( total_sent < buffer_size )
    {
        // tls plaintext payload limit is 2^14 = 16K
        uint32_t chunk_size = std::min( 16*1024U, buffer_size-total_sent );
        m_write_buffer.compact();
        co_await encrypt_and_send_application_data( (const uint8_t*)buffer + total_sent, chunk_size );
        total_sent += chunk_size;
    }
}

}
