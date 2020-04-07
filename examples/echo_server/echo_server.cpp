/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <echo_server/echo_server.hpp>

#include <iostream>

#include <libcornet/poller.hpp>
#include <libcornet/tcp_socket.hpp>

namespace net = pioneer19::cornet;

EchoSession create_echo_session( pioneer19::cornet::TcpSocket tcp_socket )
{
    char buff[1024];

    auto read_bytes = co_await tcp_socket.async_read( buff, sizeof( buff ) );
    std::cout << "echo_session read      " << read_bytes << " bytes" << std::endl;
    auto sent_bytes = co_await tcp_socket.async_write( buff, read_bytes );
    std::cout << "echo_session sent back " << sent_bytes << " bytes" << std::endl;
    tcp_socket.close();
}

EchoServerRunner EchoServer::create_runner()
{
    while( true )
    {
        sockaddr_in6 peer_addr;
        net::TcpSocket client = co_await m_server_socket.async_accept( m_poller, &peer_addr );
        std::cout << "EchoServer::create_runner() got tcp socket\n";

        auto session = create_echo_session( std::move( client ) );
        session.add_to_list( m_session_list );
    }
}

EchoServer::EchoServer( pioneer19::cornet::Poller& poller )
    :m_poller( poller )
{
    m_server_socket.bind( "::1", 10000 );
    m_server_socket.listen( poller );
}
