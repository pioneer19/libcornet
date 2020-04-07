/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
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

