/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>

#include <unistd.h>
#include <endian.h>

#include <cstdio>
#include <atomic>
#include <thread>
#include <string>
#include <array>
#include <algorithm>
#include <system_error>

void client_thread( int epoll_fd, std::atomic<bool>& stop_flag );

std::string events_string( uint32_t events_mask )
{
    constexpr std::array<uint32_t,15> event_types =
            {EPOLLIN, EPOLLOUT, EPOLLRDHUP, EPOLLPRI
             , EPOLLERR, EPOLLHUP, EPOLLET
             , EPOLLONESHOT, EPOLLWAKEUP, EPOLLEXCLUSIVE
             , EPOLLRDNORM, EPOLLRDBAND, EPOLLWRNORM
             , EPOLLWRBAND, EPOLLMSG };
    constexpr std::array<const char*,15>  event_print_types =
            { "IN", "OUT", "RDHUP", "PRI"
              , "ERR", "HUP", "ET"
              ,"ONESHOT", "WAKEUP", "EXCLUSIVE"
              , "EPOLLRDNORM", "EPOLLRDBAND", "EPOLLWRNORM"
              , "EPOLLWRBAND", "EPOLLMSG" };
    static_assert( event_types.size() == event_print_types.size()
                   , "epoll_event_types.size != epoll_event_print_types.size" );

    bool first = true;
    std::string events_string;
    for( uint32_t i = 0; i < event_types.size(); ++i )
    {
        if( events_mask & event_types[i] )
        {
            if( !first )
                events_string += ", ";
            events_string += event_print_types[i];
            first = false;
        }
    }
    return events_string;
}

int main()
{
    int epoll_fd = epoll_create1( EPOLL_CLOEXEC );
    if( epoll_fd == -1 )
        throw std::system_error( errno, std::system_category(), "failed epoll_create1()" );

    constexpr int MAX_EVENTS = 16;
    epoll_event events[ MAX_EVENTS ];

    std::atomic<bool> stop_flag {false };

    std::thread client = std::thread( client_thread, epoll_fd, std::ref(stop_flag) );
    while( !stop_flag.load( std::memory_order_relaxed ) )
    {
        constexpr int WAIT_TIMEOUT_MILLISECONDS = 10;
        int events_count = epoll_wait( epoll_fd, events, MAX_EVENTS, WAIT_TIMEOUT_MILLISECONDS );
        if( events_count == -1 )
            throw std::system_error( errno, std::system_category(), "failed epoll_wait()" );

        for( int i = 0; i < events_count; ++i )
        {
            printf( "epoll event %d, %s\n", i, events_string( events[i].events ).c_str() );
        }
    }
    client.join();

    return 0;
}

int create_server_socket( const sockaddr_in6& server_sockaddr )
{
    int sock = socket( AF_INET6, SOCK_STREAM| SOCK_CLOEXEC, 0 );
    if( sock == -1 )
        throw std::system_error( errno, std::system_category(), "failed server socket()" );

    int so_reuse = 1;
    int res = ::setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &so_reuse, sizeof( so_reuse ) );
    if( res == -1 )
        throw std::system_error(errno, std::system_category(), "set reuse addr failed" );

    res = bind( sock, (const sockaddr*)&server_sockaddr, sizeof(sockaddr_in6) );
    if( res == -1 )
        throw std::system_error( errno, std::system_category(), "failed server bind()" );
    res = listen( sock, 1024 );
    if( res == -1 )
        throw std::system_error( errno, std::system_category(), "failed server listen()" );

    return sock;
}

void client_thread( int epoll_fd, std::atomic<bool>& stop_flag )
{
    printf( "client_thread started...\n" );
    std::this_thread::sleep_for( std::chrono::milliseconds(5) );

    int client_sock = socket( AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0 );
    if( client_sock == -1 )
        throw std::system_error( errno, std::system_category(), "failed socket()" );

    printf( "socket created\n" );
    epoll_event event{};
    event.events = EPOLLET | EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLPRI;
    int res = epoll_ctl( epoll_fd, EPOLL_CTL_ADD, client_sock, &event );
    if( res == -1 )
        throw std::system_error( errno, std::system_category(), "failed epoll_ctl()" );
    std::this_thread::sleep_for( std::chrono::milliseconds(2) );

    sockaddr_in6 server_sockaddr{};
    std::fill_n((uint8_t*)&server_sockaddr, sizeof(server_sockaddr), 0 );
    server_sockaddr.sin6_family = AF_INET6;
    server_sockaddr.sin6_addr = in6addr_loopback;
    server_sockaddr.sin6_port = htobe16( 10000 );

    int server = create_server_socket( server_sockaddr );
    printf( "will call connect()\n" );
    res = connect( client_sock, (const sockaddr*)&server_sockaddr, sizeof(server_sockaddr) );
    if( res == -1 && errno != EINPROGRESS )
        throw std::system_error( errno, std::system_category(), "failed connect()" );
    std::this_thread::sleep_for( std::chrono::milliseconds(1) );

    int peer_sock = accept( server, nullptr, nullptr );
    if( peer_sock == -1 )
        throw std::system_error( errno, std::system_category(), "failed accept()" );
    printf( "socket accepted\n" );

    char buffer[] = "Hello";
    ssize_t bytes_sent = send( client_sock, buffer, sizeof(buffer), MSG_NOSIGNAL );
    if( bytes_sent == -1 )
        throw std::system_error( errno, std::system_category(), "failed send()" );
    printf( "sent %ld bytes\n", bytes_sent );
    std::this_thread::sleep_for( std::chrono::milliseconds(1) );

    char peer_buffer[1024];
    ssize_t bytes_received = recv( peer_sock, peer_buffer, sizeof(peer_buffer), 0 );
    if( bytes_received == -1 )
        throw std::system_error( errno, std::system_category(), "failed peer recv()" );
    printf( "peer received %ld bytes\nwill send back\n", bytes_received );
    bytes_sent = send( peer_sock, peer_buffer, bytes_received, MSG_NOSIGNAL );
    if( bytes_sent == -1 )
        throw std::system_error( errno, std::system_category(), "failed peer send()" );
    printf( "peer sent %ld bytes\n", bytes_sent );
    std::this_thread::sleep_for( std::chrono::milliseconds(1) );

//    bytes_received = recv( client_sock, peer_buffer, sizeof(peer_buffer), 0 );
//    if( bytes_received == -1 )
//        throw std::system_error( errno, std::system_category(), "failed recv()" );
//    printf( "client received %ld bytes\n", bytes_received );
//    std::this_thread::sleep_for( std::chrono::milliseconds(4) );

//    printf( "will shutdown peer rd\n" );
//    shutdown( peer_sock, SHUT_RD );
//    std::this_thread::sleep_for( std::chrono::milliseconds(3) );

//    printf( "will shutdown peer wr\n" );
//    shutdown( peer_sock, SHUT_WR );
//    std::this_thread::sleep_for( std::chrono::milliseconds(3) );

//    printf( "will shutdown peer rdwr\n" );
//    shutdown( peer_sock, SHUT_RDWR );
//    std::this_thread::sleep_for( std::chrono::milliseconds(3) );

//    printf( "will shutdown client rd\n" );
//    shutdown( client_sock, SHUT_RD );
//    std::this_thread::sleep_for( std::chrono::milliseconds(3) );

//    printf( "will shutdown client wr\n" );
//    shutdown( client_sock, SHUT_WR );
//    std::this_thread::sleep_for( std::chrono::milliseconds(3) );

//    printf( "will shutdown client rdwr\n" );
//    shutdown( client_sock, SHUT_RDWR );
//    std::this_thread::sleep_for( std::chrono::milliseconds(4) );

    printf( "will close peer\n" );
    close( peer_sock );
    std::this_thread::sleep_for( std::chrono::milliseconds(1) );

    bytes_received = recv( client_sock, peer_buffer, sizeof(peer_buffer), 0 );
    if( bytes_received == -1 )
        throw std::system_error( errno, std::system_category(), "failed recv()" );
    printf( "client received %ld bytes\n", bytes_received );
    std::this_thread::sleep_for( std::chrono::milliseconds(4) );

    bytes_sent = send( client_sock, buffer, sizeof(buffer), MSG_NOSIGNAL );
    if( bytes_sent == -1 )
        throw std::system_error( errno, std::system_category(), "failed send()" );
    printf( "client sent %ld bytes in closed socket\n", bytes_sent );
    std::this_thread::sleep_for( std::chrono::milliseconds(4) );

    std::this_thread::sleep_for( std::chrono::milliseconds(50) );
    stop_flag.store( true, std::memory_order_relaxed );
}
