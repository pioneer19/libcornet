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
#include <libcornet/tls/tls_socket.hpp>
#include <libcornet/tls/key_store.hpp>
namespace net = pioneer19::cornet;

#include <libcornet/coroutines_utils.hpp>
namespace coroutines = pioneer19::coroutines;

coroutines::CommonCoroutine async_session( net::Poller& poller, const char* ip_address )
{
    net::tls13::TlsSocket tls_socket{};
    tls_socket.bind( ip_address, 10000 );
    tls_socket.listen( poller );
    std::cout << "Tls server listening\n";

    net::tls13::TlsSocket client_socket = co_await tls_socket.async_accept( poller, nullptr, new net::tls13::SingleDomainKeyStore(
            SNI_HOSTNAME, "./key.pem", "./cert.pem", "./cert_chain.pem") );
    printf( "tls server got connected socket\n"     );

    uint8_t buffer[1024];
    auto bytes_read = co_await client_socket.async_read( buffer, sizeof(buffer) );
    printf( "tls server read %u bytes from client socket\n", bytes_read );
    co_await client_socket.async_write( buffer, bytes_read );

    poller.stop();
}

int main()
{
    std::cout << "Polling TLS server (single thread)\n";

    net::Poller poller;

    auto coro = async_session( poller, "::1" );

    poller.run_on_signal( SIGINT, [&coro,&poller](){ coro.stop(); poller.stop();} );
    poller.run_on_signal( SIGHUP, [&coro,&poller](){ coro.stop(); poller.stop();} );

    poller.run();

    return 0;
}
