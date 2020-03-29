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

#include <libcornet/peer_resolver.hpp>

#include <algorithm>

namespace pioneer19::cornet
{

PeerResolver::PeerResolver( const char* hostname ) noexcept
{
    init_peer_in6_addr();
    resolve_hostname( hostname );
}

void PeerResolver::resolve_hostname( const char* hostname )
{
    addrinfo hints = {};
    std::fill_n( (uint8_t*)&hints, sizeof(hints), 0 );
    /*
     * AI_ADDRCONFIG + AF_UNSPEC will produce both v4 and v6 addresses
     * but only if they configured on interfaces (so v4 only node will skip v6 addresses)
     * This also means that it will produce mixed v4 and v6 addresses, but I want to use v4mapped
     * to v6 sockets, so I will mmap it myself
     */
    hints.ai_flags = AI_ADDRCONFIG | AI_ALL | AI_V4MAPPED;
    hints.ai_family = AF_UNSPEC;     // AF_INET and AF_INET6
    hints.ai_socktype = SOCK_STREAM; // to skip duplicates for STREAM and DATAGRAM
    hints.ai_protocol = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    int ai_res = getaddrinfo( hostname, NULL, &hints, &m_addr_info_list );
    if( ai_res == 0 )
        m_current = m_addr_info_list;
    else
        m_error_str = gai_strerror( ai_res );
}

PeerResolver::~PeerResolver() noexcept
{
    if( m_addr_info_list != nullptr )
        freeaddrinfo( m_addr_info_list );
}

PeerResolver::operator bool() const noexcept
{
    return m_current != nullptr;
}

void PeerResolver::next() noexcept
{
    m_current = m_addr_info_list->ai_next;
}

const in6_addr& PeerResolver::ip6_addr() noexcept
{
    if( m_current->ai_family == AF_INET6 )
        return ((sockaddr_in6*)m_current->ai_addr)->sin6_addr;

    // create v4mapped address from in_addr (copy v4 octets to in6_addr tail)
    memcpy( m_peer_in6_addr.s6_addr+12, &((sockaddr_in*)m_current->ai_addr)->sin_addr, 4 );

    return m_peer_in6_addr;
}

void PeerResolver::init_peer_in6_addr() noexcept
{
    std::fill_n( (uint8_t*)&m_peer_in6_addr, sizeof(m_peer_in6_addr), 0 );
    // for v4mapped address ::ffff:10.128.1.1
    m_peer_in6_addr.__in6_u.__u6_addr8[10] = 0xff;
    m_peer_in6_addr.__in6_u.__u6_addr8[11] = 0xff;
}

sockaddr_in6 PeerResolver::sockaddr( uint16_t port ) noexcept
{
    sockaddr_in6 peer_addr = {};

    std::fill( reinterpret_cast<char*>(&peer_addr)
               , reinterpret_cast<char*>(&peer_addr) + sizeof(peer_addr), 0 );
    peer_addr.sin6_family = AF_INET6;
    peer_addr.sin6_addr   = ip6_addr();
    peer_addr.sin6_port   = htobe16( port );

    return peer_addr;
}

}
