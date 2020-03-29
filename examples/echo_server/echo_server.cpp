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

#include <echo_server/echo_server.hpp>

#include <iostream>

#include <libcornet/poller.hpp>
#include <libcornet/tcp_socket.hpp>

namespace net = pioneer19::cornet;

EchoSession create_echo_session( pioneer19::cornet::TcpSocket tcp_socket )
{
    char buff[1024];

    auto read_bytes = co_await tcp_socket.async_read(  buff, sizeof( buff ) );
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
