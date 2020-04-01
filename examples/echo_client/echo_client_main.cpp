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

#include <unistd.h>
#include <iostream>

#include <libcornet/poller.hpp>
#include <libcornet/tcp_socket.hpp>
namespace net = pioneer19::cornet;

#include <libcornet/coroutines_utils.hpp>
namespace coroutines = pioneer19::coroutines;

coroutines::CommonCoroutine async_session( net::Poller& poller, const char* hostname )
{
    net::TcpSocket client;
    co_await client.async_connect( poller, "localhost", 10000 );
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
