/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <unistd.h>
#include <iostream>

#include <libcornet/poller.hpp>
#include <libcornet/tcp_socket.hpp>
namespace net = pioneer19::cornet;

#include <pioneer19_utils/coroutines_utils.hpp>
using pioneer19::CommonCoroutine;

CommonCoroutine async_session( net::Poller& poller, const char* hostname )
{
    net::TcpSocket client;
    co_await client.async_connect( poller, hostname, 10000 );
    std::cout << "async_session connected tcp socket\n";

    char buff[] = {"Hello, World\n"};

    auto sent_bytes = co_await client.async_write( buff, sizeof(buff)-1 );
    std::cout << "socket sent      " << sent_bytes << " bytes" << std::endl;
    auto read_bytes = co_await client.async_read( buff, sent_bytes );
    std::cout << "socket read back " << read_bytes << " bytes" << std::endl;
    client.close();

    poller.stop();
}

int main()
{
    std::cout << "Polling echo client (single thread)\n";

    net::Poller poller;

    auto coro = async_session( poller, "localhost" );

    poller.run_on_signal( SIGINT, [&coro,&poller](){ coro.stop(); poller.stop();} );
    poller.run_on_signal( SIGHUP, [&coro,&poller](){ coro.stop(); poller.stop();} );

    poller.run();

    return 0;
}
