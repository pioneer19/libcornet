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
