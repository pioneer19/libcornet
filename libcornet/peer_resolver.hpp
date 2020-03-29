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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

namespace pioneer19::cornet
{
/**
 * @class PeerResolver synchronous resolver
 *
 * @code{.cpp}
 * PeerResolver resolver( hostname );
 * if( !resolver )
 *     throw std::runtime_error(
 *               std::string( "hostname \"" ) + hostname + "\"resolution failed: "+resolver.error_str() );
 * while( resolver )
 * {
 *     const sockaddr_in6& peer_addr = resolver.sockaddr( port_num );
 *     bool  connected = co_await async_connect( poller, &peer_addr );
 *     if( connected )
 *         co_return true;
 *     resolver.next()
 * }
 * co_return false;
 * @endcode
 */
class PeerResolver
{
public:
    explicit PeerResolver( const char* hostname ) noexcept;
    ~PeerResolver() noexcept;

    explicit operator bool() const noexcept;
    void next() noexcept;
    sockaddr_in6 sockaddr( uint16_t port ) noexcept;
    [[nodiscard]]
    const char* error_str() const noexcept;

    PeerResolver() = delete;
    PeerResolver( PeerResolver&& ) = delete;
    PeerResolver& operator=( PeerResolver&& ) = delete;
    PeerResolver( const PeerResolver& ) = delete;
    PeerResolver& operator=( const PeerResolver& ) = delete;

private:
    void init_peer_in6_addr() noexcept;
    void resolve_hostname( const char* hostname );
    const in6_addr& ip6_addr() noexcept;

    addrinfo* m_addr_info_list = nullptr;
    addrinfo* m_current = nullptr;
    in6_addr  m_peer_in6_addr = {};
    const char*  m_error_str = nullptr;
};

inline const char* PeerResolver::error_str() const noexcept
{
    return m_error_str;
}

}
