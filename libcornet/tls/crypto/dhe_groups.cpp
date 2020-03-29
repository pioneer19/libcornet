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

#include <libcornet/tls/crypto/dhe_groups.hpp>

#include <charconv>
#include <string>
#include <stdexcept>

#include <openssl/ec.h>
#include <openssl/err.h>

namespace pioneer19::cornet::tls13::crypto
{

DheGroup::DheGroup( record::NamedGroup named_group )
        :m_named_group{ named_group }
{
    create_key( named_group );
}

DheGroup::~DheGroup() noexcept
{
    if( m_key_pair )
        EVP_PKEY_free( m_key_pair );
}

void DheGroup::set_dhe_group( record::NamedGroup named_group )
{
    if( m_key_pair )
    {
        EVP_PKEY_free( m_key_pair );
        m_key_pair = nullptr;
    }
    create_key( named_group );
    m_named_group = named_group;
}

void DheGroup::create_key( record::NamedGroup named_group )
{
    EVP_PKEY_CTX* pctx = nullptr;
    switch( named_group )
    {
        case record::NamedGroup::X25519:
            pctx = EVP_PKEY_CTX_new_id( EVP_PKEY_X25519, nullptr );
            EVP_PKEY_keygen_init( pctx );
            break;
        case record::NamedGroup::X448:
            pctx = EVP_PKEY_CTX_new_id( EVP_PKEY_X448, nullptr );
            EVP_PKEY_keygen_init( pctx );
            break;
        case record::NamedGroup::SECP256R1:
        {
            pctx = EVP_PKEY_CTX_new_id( EVP_PKEY_EC, nullptr );
            if( pctx == nullptr )
            {
                printf( "EVP_PKEY_CTX_new_id failed\n" );
                ERR_print_errors_fp( stderr );
            }
            if( EVP_PKEY_keygen_init( pctx ) != 1 )
            {
                printf( "EVP_PKEY_keygen_init failed\n" );
                ERR_print_errors_fp( stderr );
            }
            if( EVP_PKEY_CTX_set_ec_paramgen_curve_nid( pctx, NID_X9_62_prime256v1 ) != 1)
            {
                printf( "EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed\n" );
                ERR_print_errors_fp( stderr );
            }
            break;
        }
        case record::NamedGroup::SECP384R1:
            pctx = EVP_PKEY_CTX_new_id( EVP_PKEY_EC, nullptr );
            EVP_PKEY_keygen_init( pctx );
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid( pctx, NID_secp384r1 );
            break;
        case record::NamedGroup::SECP521R1:
            pctx = EVP_PKEY_CTX_new_id( EVP_PKEY_EC, nullptr );
            EVP_PKEY_keygen_init( pctx );
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid( pctx, NID_secp521r1 );
            break;
        case record::NamedGroup::FFDHE2048:
        case record::NamedGroup::FFDHE3072:
        case record::NamedGroup::FFDHE4096:
        case record::NamedGroup::FFDHE6144:
        case record::NamedGroup::FFDHE8192:
        default:
            char buff[4];
            std::to_chars(buff, buff+sizeof(buff), static_cast<uint16_t>(named_group),16);
            throw std::out_of_range("DheGroup::create_key got unknown/unimplemented group 0x"
                                    +std::string(buff, sizeof(buff)) );
    }
    if( EVP_PKEY_keygen( pctx, &m_key_pair ) != 1 )
    {
        printf( "EVP_PKEY_keygen failed\n" );
        ERR_print_errors_fp( stderr );
    }
    EVP_PKEY_CTX_free( pctx );
    if( pctx == nullptr || m_key_pair == nullptr )
        ERR_print_errors_fp( stderr );
}

uint32_t DheGroup::derive_secret( record::NamedGroup named_group
        ,const uint8_t* raw_public_key, uint16_t key_size, uint8_t* out_shared_secret ) noexcept
{
    /* Create the context for the shared secret derivation */
    EVP_PKEY_CTX *derive_ctx = EVP_PKEY_CTX_new( m_key_pair, nullptr);
    if( derive_ctx == nullptr )
        std::runtime_error( ERR_error_string( ERR_get_error(), nullptr ) );

    /* Initialise */
    if( EVP_PKEY_derive_init(derive_ctx) != 1 )
        std::runtime_error( ERR_error_string( ERR_get_error(), nullptr ) );

    EVP_PKEY* peer_key = nullptr;
    switch( named_group )
    {
        case record::NamedGroup::X25519:
            peer_key = EVP_PKEY_new_raw_public_key( NID_X25519, nullptr, raw_public_key, key_size );
            break;
        case record::NamedGroup::X448:
            peer_key = EVP_PKEY_new_raw_public_key( NID_X448, nullptr, raw_public_key, key_size );
            break;
        /*
         * For secp256r1 and other EC curves
         * https://security.stackexchange.com/questions/209794/converting-a-raw-ec-public-key-into-evp-pkey-using-openssl
         * https://stackoverflow.com/questions/18155559/how-does-one-access-the-raw-ecdh-public-key-private-key-and-params-inside-opens
         */
        case record::NamedGroup::SECP256R1:
        case record::NamedGroup::SECP384R1:
        case record::NamedGroup::SECP521R1:
            peer_key = EVP_PKEY_new();
            if( EVP_PKEY_copy_parameters( peer_key, m_key_pair ) != 1 )
            {
                printf( "EVP_PKEY_copy_parameters failed\n" );
                ERR_print_errors_fp( stderr );
            }
            if( EVP_PKEY_set1_tls_encodedpoint( peer_key, raw_public_key, key_size ) != 1 )
            {
                printf( "EVP_PKEY_set1_tls_encodedpoint failed\n" );
                ERR_print_errors_fp( stderr );
            }
            break;
        default:
            throw std::runtime_error( "DheGroup::derive_secret for unknown group "
                                      +std::to_string(static_cast<uint16_t>(named_group)) );
    }
    if( peer_key == nullptr )
        throw std::runtime_error( ERR_error_string( ERR_get_error(), nullptr ) );

    /* Provide the peer public key */
    if( EVP_PKEY_derive_set_peer( derive_ctx, peer_key) != 1 )
        throw std::runtime_error( ERR_error_string( ERR_get_error(), nullptr ) );

    size_t shared_secret_len = 0;
    /* Determine buffer length for shared secret */
    if( EVP_PKEY_derive( derive_ctx, nullptr, &shared_secret_len) != 1 )
        throw std::runtime_error( ERR_error_string( ERR_get_error(), nullptr ) );

//    /* Create the buffer */
//    if(NULL == (secret = OPENSSL_malloc(*secret_len))) handleErrors();

    /* Derive the shared secret */
    if( EVP_PKEY_derive(derive_ctx, out_shared_secret, &shared_secret_len) != 1 )
        throw std::runtime_error( ERR_error_string( ERR_get_error(), nullptr ) );

    EVP_PKEY_free( peer_key );
    EVP_PKEY_CTX_free( derive_ctx );

    return shared_secret_len;
}

uint32_t DheGroup::copy_public_key( uint8_t* dst ) noexcept
{
    switch( m_named_group )
    {
        case record::NamedGroup::X25519:
        case record::NamedGroup::X448:
        {
            size_t key_size = public_key_size();
            int res = EVP_PKEY_get_raw_public_key( m_key_pair, dst, &key_size );
            if( res != 1 )
            {
                printf( "res %d\n", res );
                char err_buffer[1024];
                std::string err_string{ ERR_error_string( ERR_get_error(), err_buffer ) };
                throw std::runtime_error( "DheGroup::copy_public_key() failed: " + err_string );
            }
            return key_size;
        }
        default:
        {
            uint8_t* raw_key = nullptr;
            auto key_size = EVP_PKEY_get1_tls_encodedpoint( m_key_pair, &raw_key );
            std::copy_n( raw_key, key_size, dst );
            OPENSSL_free( raw_key );

            return key_size;
        }
    }
}

uint32_t DheGroup::public_key_size() const noexcept
{
    switch( m_named_group )
    {
        case record::NamedGroup::X25519:
            return 32;
        case record::NamedGroup::X448:
            return 56;
        /*
         * struct {
         *     uint8 legacy_form = 4;
         *     opaque X[coordinate_length];
         *     opaque Y[coordinate_length];
         * } UncompressedPointRepresentation;
         */
        case record::NamedGroup::SECP256R1:
            return 65; // uint8 + 2 * 32
        case record::NamedGroup::SECP384R1:
            return 97; // uint8 + 2 * 48
        case record::NamedGroup::SECP521R1:
            return 133; // uint8 + 2 * 66
        default:
            throw std::runtime_error( "DheGroup::public_key_size for unknown group "
                                      +std::to_string(static_cast<uint16_t>(m_named_group) ) );
    }
}

bool DheGroup::is_supported( record::NamedGroup named_group ) noexcept
{
    switch( named_group )
    {
        case record::NamedGroup::X25519:
        case record::NamedGroup::X448:
        case record::NamedGroup::SECP256R1:
        case record::NamedGroup::SECP384R1:
        case record::NamedGroup::SECP521R1:
            return true;
        default:
            return false;
    }
}

}
