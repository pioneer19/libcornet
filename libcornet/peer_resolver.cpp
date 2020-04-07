/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
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
