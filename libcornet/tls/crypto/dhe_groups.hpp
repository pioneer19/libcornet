/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once

#include <openssl/evp.h>

#include <libcornet/tls/types.hpp>

namespace pioneer19::cornet::tls13::crypto
{

class DheGroup
{
public:
    DheGroup() = default;
    explicit DheGroup( record::NamedGroup named_group );
    ~DheGroup() noexcept ;

    void set_dhe_group( record::NamedGroup named_group=record::NamedGroup::X25519 );
    static bool is_supported( record::NamedGroup ) noexcept;
    [[nodiscard]]
    record::NamedGroup named_group() const noexcept { return m_named_group; }

    uint32_t derive_secret( record::NamedGroup named_group
            ,const uint8_t* raw_public_key, uint16_t key_size, uint8_t* out_shared_secret ) noexcept;
    uint32_t copy_public_key( uint8_t* dst ) noexcept;
    [[nodiscard]]
    uint32_t public_key_size() const noexcept;

    DheGroup( DheGroup&& )            = delete;
    DheGroup& operator=( DheGroup&& ) = delete;
    DheGroup( const DheGroup& )            = delete;
    DheGroup& operator=( const DheGroup& ) = delete;

private:
    void create_key( record::NamedGroup named_group );

    EVP_PKEY* m_key_pair = nullptr;
    record::NamedGroup m_named_group = record::NamedGroup::TLS_PRIVATE_NAMED_GROUP;
};

}
