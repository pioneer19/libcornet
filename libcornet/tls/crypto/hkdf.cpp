/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <libcornet/tls/crypto/hkdf.hpp>

#include <endian.h>

#include <algorithm>

namespace pioneer19::cornet::tls13::crypto
{

/*
 * rfc5869
 * HKDF-Extract(salt, IKM) -> PRK
 * Options:
 *    Hash     a hash function; HashLen denotes the length of the
 *             hash function output in octets
 * Inputs:
 *    salt     optional salt value (a non-secret random value);
 *             if not provided, it is set to a string of HashLen zeros.
 *    IKM      input keying material
 * Output:
 *    PRK      a pseudorandom key (of HashLen octets)
 *
 * The output PRK is calculated as follows:
   PRK = HMAC-Hash(salt, IKM)
 */
unsigned hkdf_extract( const EVP_MD* evp_md
        ,const unsigned char* salt, size_t salt_len
        ,const unsigned char* ikm,  size_t ikm_len
        ,unsigned char* prk ) noexcept
{
    unsigned prk_len;

    if( !HMAC( evp_md, salt, salt_len, ikm, ikm_len, prk, &prk_len ) )
        return 0;

    return prk_len;
}

/*
 * rfc5869
 * HKDF-Expand(PRK, info, L) -> OKM
 * Options:
 * Hash     a hash function; HashLen denotes the length of the
 *          hash function output in octets
 * Inputs:
 *    PRK      a pseudorandom key of at least HashLen octets
 *             (usually, the output from the extract step)
 *    info     optional context and application specific information
 *             (can be a zero-length string)
 *    L        length of output keying material in octets
 *             (<= 255*HashLen)
 * Output:
 *    OKM      output keying material (of L octets)
 * The output OKM is calculated as follows:
 * N = ceil(L/HashLen)
 * T = T(1) | T(2) | T(3) | ... | T(N)
 * OKM = first L octets of T
 * where:
 * T(0) = empty string (zero length)
 * T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
 * T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
 * T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
 * ...
 * (where the constant concatenated to the end of each T(n) is a
 * single octet.)
 */
unsigned hkdf_expand( const EVP_MD* evp_md
        ,const unsigned char* prk, size_t prk_len
        ,const unsigned char* info, size_t info_len
        ,unsigned char* okm, size_t okm_len ) noexcept
{
    unsigned digest_size = EVP_MD_size( evp_md);
    unsigned block_count = 1 + ( okm_len - 1 ) / digest_size;
    if( block_count > 255 )
        return 0;

    HMAC_CTX* hmac;
    if( (hmac = HMAC_CTX_new() ) == nullptr )
        return 0;

    auto cleanup = [hmac] ( unsigned res ) { HMAC_CTX_free( hmac); return res; };

    if( !HMAC_Init_ex(hmac, prk, prk_len, evp_md, nullptr) )
        return cleanup( 0);

    unsigned char tmp_block[EVP_MAX_MD_SIZE];
    for( unsigned block_num = 1; block_num <= block_count ; block_num++)
    {
        if ( block_num > 1) {
            if (!HMAC_Init_ex(hmac, nullptr, 0, nullptr, nullptr))
                return cleanup( 0);

            if (!HMAC_Update(hmac, tmp_block, digest_size))
                return cleanup( 0);
        }

        if( !HMAC_Update(hmac, info, info_len) )
            return cleanup( 0);

        if( !HMAC_Update( hmac, reinterpret_cast<const unsigned char*>(&block_num), 1) )
            return cleanup( 0);

        if( !HMAC_Final(hmac, tmp_block, nullptr) )
            return cleanup( 0);

        unsigned bytes_to_copy = ( block_num < block_count )
                                 ? digest_size : ( okm_len - (block_count-1)*digest_size );
        unsigned char* dst = okm + (block_num - 1) * digest_size;
        std::copy_n( tmp_block, bytes_to_copy, dst );
    }

    return cleanup( okm_len );
}

/*
 * HKDF-Expand-Label(Secret, Label, Context, Length) =
 *          HKDF-Expand(Secret, HkdfLabel, Length)
 *     Where HkdfLabel is specified as:
 *     struct {
 *         uint16 length = Length;
 *         opaque label<7..255> = "tls13 " + Label;
 *         opaque context<0..255> = Context;
 *     } HkdfLabel;
 *
 * Derive-Secret(Secret, Label, Messages) =
 *          HKDF-Expand-Label(Secret, Label,
 *                            Transcript-Hash(Messages), Hash.length)
 */
unsigned hkdf_expand_label( const EVP_MD* evp_md
        ,const unsigned char* secret, size_t secret_size
        ,const unsigned char* label, size_t label_size
        ,const unsigned char* context, size_t context_size
        ,unsigned char* out, size_t out_size ) noexcept
{
    unsigned char hkdf_label[ sizeof(uint16_t)  // uint16 length = Length;
                              + 1 + 255         // opaque label<7..255>, 1 byte len + 255
                              + 1 + 255 ];      // opaque context<0..255> = Context;
    static const unsigned char label_prefix[] = "tls13 ";
    unsigned hkdf_label_size = 0;
    {
        auto* length_ptr = reinterpret_cast<uint16_t*>( hkdf_label );
        *length_ptr = htobe16( static_cast<uint16_t>(out_size) );
        unsigned offset = sizeof(uint16_t);
        { // opaque label<7..255>, 1 byte len + 255
            uint8_t* label_vector_len_ptr = ( hkdf_label + offset );
            *label_vector_len_ptr = (sizeof( label_prefix ) - 1) + label_size;
            offset += sizeof( uint8_t );

            std::copy_n( label_prefix, sizeof(label_prefix)-1, hkdf_label+offset );
            offset += sizeof(label_prefix)-1;
            std::copy_n( label, label_size, hkdf_label+offset );
            offset += label_size;
        }
        { //opaque context<0..255> = Context;
            uint8_t* context_vector_len_ptr = ( hkdf_label + offset );
            *context_vector_len_ptr = context_size;
            offset += sizeof( uint8_t );

            std::copy_n( context, context_size, hkdf_label+offset );
            offset += context_size;
        }
        hkdf_label_size = offset;
    }

    return hkdf_expand( evp_md, secret, secret_size, hkdf_label, hkdf_label_size, out, out_size );
}
/*
 * Derive-Secret(Secret, Label, Messages) =
 *          HKDF-Expand-Label(Secret, Label,
 *                            Transcript-Hash(Messages), Hash.length)
 */
unsigned derive_secret( const EVP_MD* evp_md
        ,const unsigned char* secret, size_t secret_size
        ,const unsigned char* label, size_t label_size
        ,const unsigned char* messages, size_t messages_size
        ,unsigned char* out ) noexcept
{
    EVP_MD_CTX *hash_ctx = EVP_MD_CTX_new();
    unsigned char hash[ EVP_MAX_MD_SIZE ];
    uint32_t hash_size = sizeof(hash);
    if( hash_ctx == nullptr
        || EVP_DigestInit_ex( hash_ctx, evp_md, nullptr ) == 0
        || EVP_DigestUpdate( hash_ctx, messages, messages_size ) == 0
        || EVP_DigestFinal_ex( hash_ctx, hash, &hash_size ) == 0 )
    {
        EVP_MD_CTX_free( hash_ctx );
        return 0;
    }
    EVP_MD_CTX_free( hash_ctx );

    return hkdf_expand_label( evp_md
                              ,secret, secret_size
                              ,label, label_size
                              ,hash, EVP_MD_size( evp_md )
                              ,out, EVP_MD_size( evp_md ) );
}

}
