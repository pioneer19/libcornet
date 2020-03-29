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

#include <tls_client/tls_client.hpp>

#include <iostream>
#include <iterator>

#include <libcornet/config.hpp>
#include <libcornet/tls/tls_socket.hpp>
namespace net = pioneer19::cornet;
namespace tls = net::tls13;

TlsServerRunner TlsClient::create_runner()
{
    tls::TlsSocket tls_socket{};
    // connect hostname and TLS SNI can differ
    if( !co_await tls_socket.async_connect( m_poller, "localhost", 10000, SNI_HOSTNAME ) )
//    if( !co_await client.async_connect( m_poller, "localhost", 10000 ) )
    {
        std::cout << "TlsClient::create_runner() failed connect " << strerror(errno) << "\n";
        ::exit( EXIT_FAILURE );
    }
    std::cout << "TlsClient::create_runner() connected\n";

    uint8_t get_request[] = "GET / HTTP1.1\r\n"
                            "Host: " SNI_HOSTNAME "\r\n\r\n";
    co_await tls_socket.async_write( get_request, sizeof(get_request) - 1 );

    uint8_t read_buffer[16*1024];
        auto res = co_await tls_socket.async_read( read_buffer, sizeof(read_buffer) );
    std::cout << "TlsClient::create_runner read " << res << " bytes\n";
    std::cout << (const char*)read_buffer << "\n";

    m_poller.stop();
}

TlsClient::TlsClient( net::Poller& poller )
    :m_poller( poller )
{}

