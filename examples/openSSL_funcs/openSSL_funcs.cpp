/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <cstdio>
#include <algorithm>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <chrono>
#include <thread>
#include <stdexcept>

#include <openSSL_funcs/cpu_utils.hpp>

//#include <android/openssl/curve25519.h>

void random_bytes( uint8_t* buff, uint32_t size )
{
    int res = RAND_bytes( buff, size );
    if( res != 1 )
        throw std::runtime_error( ERR_error_string( ERR_get_error(), nullptr ) );
}

int main()
{
    uint64_t begin_tsc = 0, end_tsc = 0;
    printf( "tsc calibration\n" );

    auto chrono_begin = std::chrono::steady_clock::now();
    begin_tsc = rdtsc();
    std::this_thread::sleep_for( std::chrono::milliseconds(100) );
    end_tsc = rdtsc();
    auto chrono_end   = std::chrono::steady_clock::now();
    std::chrono::duration<double> diff = chrono_end - chrono_begin;

    auto ticks_per_second = static_cast<size_t>((end_tsc-begin_tsc)/diff.count());
    printf( "tsc per second %zd\n", ticks_per_second );

    /* Generate private and public key */
    EVP_PKEY* pkey = NULL;
    // for custom curves X25519, X448
    //EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id( NID_X25519, NULL );
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id( EVP_PKEY_X25519, NULL );
    EVP_PKEY_keygen_init( pctx );

//    // for EC curves
////    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id( EVP_PKEY_EC, NULL );
////    EVP_PKEY_keygen_init(pctx);
////    EVP_PKEY_CTX_set_ec_paramgen_curve_nid( pctx, NID_X9_62_prime256v1 );
//
    begin_tsc = rdtsc();
    EVP_PKEY_keygen( pctx, &pkey );
    end_tsc = rdtsc();
    printf( "EVP_PKEY_keygen got %ld ticks\n", end_tsc-begin_tsc );

    begin_tsc = rdtsc();
    EVP_PKEY_keygen( pctx, &pkey );
    end_tsc = rdtsc();
    printf( "EVP_PKEY_keygen got %ld ticks\n", end_tsc-begin_tsc );

    EVP_PKEY_CTX_free( pctx );

    EC_KEY * ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    //EC_KEY * ec_key = EC_KEY_new_by_curve_name( NID_X25519 );
    if( ec_key == nullptr )
    {
        printf( "error in EC_KEY_new_by_curve_name: %s\n"
                ,ERR_error_string( ERR_get_error(), nullptr ));
        goto err;
    }
    begin_tsc = rdtsc();
    {
        int res = EC_KEY_generate_key( ec_key );
        if( res == 0 )
        {
            printf( "error in EC_KEY_generate_key: %s\n"
                    ,ERR_error_string( ERR_get_error(), nullptr ));
            goto err;
        }
        end_tsc = rdtsc();
        printf( "EC_KEY_generate_key got %ld ticks\n", end_tsc - begin_tsc );
    }

    begin_tsc = rdtsc();
    EC_KEY_generate_key(ec_key);
    end_tsc = rdtsc();
    printf( "EC_KEY_generate_key got %ld ticks\n", end_tsc-begin_tsc );

    err:
    /* Print keys to stdout */
    printf( "\nAlice's PRIVATE KEY:\n" );
    PEM_write_PrivateKey( stdout, pkey, NULL, NULL, 0, NULL, NULL );
    printf( "\nAlice's PUBKEY:\n" );
    PEM_write_PUBKEY( stdout, pkey );

    uint8_t rnd[32];
    std::fill( rnd, rnd+sizeof(rnd), 0 );

    begin_tsc = rdtsc();
    random_bytes( rnd, sizeof(rnd) );
    end_tsc = rdtsc();
    printf( "random_bytes() got %ld ticks\n", end_tsc-begin_tsc );

    begin_tsc = rdtsc();
    random_bytes( rnd, sizeof(rnd) );
    end_tsc = rdtsc();
    printf( "random_bytes() got %ld ticks\n", end_tsc-begin_tsc );


    // for boringssl benchmarks
//    uint8_t out_public_value[32];
//    uint8_t out_private_key[32];
//
//    begin_tsc = rdtsc();
//    X25519_keypair( out_public_value, out_private_key );
//    end_tsc = rdtsc();
//    printf( "X25519_keypair() got %ld ticks\n", end_tsc-begin_tsc );
//
//    begin_tsc = rdtsc();
//    X25519_keypair( out_public_value, out_private_key );
//    end_tsc = rdtsc();
//    printf( "X25519_keypair() got %ld ticks\n", end_tsc-begin_tsc );

    return 0;
}
