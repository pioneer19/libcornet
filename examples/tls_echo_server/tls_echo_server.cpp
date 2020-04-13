/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <unistd.h>

#include <cstdio>
#include <string>
#include <memory>

#include <libcornet/tls/tls_socket.hpp>
#include <libcornet/poller.hpp>
namespace net = pioneer19::cornet;

#include <libcornet/coroutines_utils.hpp>
namespace coroutines = pioneer19::coroutines;

coroutines::LinkedCoroutine run_session( net::tls13::TlsSocket&& tls_socket )
{
    uint8_t buffer[1024];
    auto bytes_read = co_await tls_socket.async_read( buffer, sizeof(buffer) );
    printf( "tls server read %u bytes from client socket\n", bytes_read );
    co_await tls_socket.async_write( buffer, bytes_read );
}

coroutines::CommonCoroutine run_server( net::Poller& poller, const char* ip_address, size_t session_count )
{
    net::tls13::TlsSocket tls_socket{};
    tls_socket.bind( ip_address, 10000 );
    tls_socket.listen( poller );
    printf( "Tls server listening\n" );

    coroutines::LinkedCoroutine::List tls_sessions_list;
    std::unique_ptr<net::tls13::SingleDomainKeyStore> key_store { new net::tls13::SingleDomainKeyStore(
            SNI_HOSTNAME, "./key.pem", "./cert.pem", "./cert_chain.pem" ) };

    for( size_t i = 0; session_count==0 || i < session_count; ++i ) // infinite for session_count == 0
    {
        net::tls13::TlsSocket client_socket = co_await tls_socket.async_accept(
                poller, nullptr, key_store.get() );
        printf( "tls server got connected socket, (count=%lu)\n", i );

        auto session = run_session( std::move( client_socket ) );
        session.link_promise( tls_sessions_list );
    }
    // FIXME: close server socket and co_await while tls_session_list become empty

    poller.stop();
}

int main( int argc, char *argv[] )
{
    size_t session_limit = 0; // 0 - is unlimited
    try
    {
        if( argc >= 2 )
            session_limit = std::stoul( argv[1] );
    }
    catch( const std::exception& ex )
    {
        printf( "failed convert first argument \"%s\" to number\n"
                "usage: %s session_count\n", argv[1], argv[0] );
        ::exit(EXIT_FAILURE );
    }

    printf( "Polling tls echo server (single thread)\n" );

    net::Poller poller;

    auto coro = run_server( poller, "::1", session_limit );

    poller.run_on_signal( SIGINT, [&coro,&poller](){ coro.stop(); poller.stop();} );
    poller.run_on_signal( SIGHUP, [&coro,&poller](){ coro.stop(); poller.stop();} );
    //poller.run_on_signal( SIGINT, [](){puts("SIGQUIT");} );
    poller.run();

    return 0;
}
