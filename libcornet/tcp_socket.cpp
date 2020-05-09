/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <libcornet/tcp_socket.hpp>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <cassert>
#include <cerrno>
#include <unistd.h>

#include <algorithm>
#include <system_error>

#include <libcornet/peer_resolver.hpp>

namespace pioneer19::cornet
{

TcpSocket::TcpSocket()
{
    create_socket();
}

void TcpSocket::create_socket()
{
    m_socket_fd = socket( AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0 );
    if( m_socket_fd == -1 )
        throw std::system_error(errno, std::system_category(), "failed create_socket socket" );
    m_poller_cb = new PollerCb;
}

TcpSocket::TcpSocket( TcpSocket&& other ) noexcept
    :m_poller_cb( std::move(other.m_poller_cb) )
    ,m_socket_fd( other.m_socket_fd )
{
    other.m_socket_fd = -1;
}

TcpSocket& TcpSocket::operator=( TcpSocket&& other ) noexcept
{
    if( this != &other )
    {
        close();
        std::swap( m_socket_fd, other.m_socket_fd );
        std::swap( m_poller_cb, other.m_poller_cb );
    }
    return *this;
}

TcpSocket::TcpSocket( int socket_fd, Poller* poller )
        :m_poller_cb( new PollerCb )
        ,m_socket_fd( socket_fd )
{
    if( poller )
        poller->add_socket( *this, m_poller_cb );
}

void TcpSocket::bind( const char* ip_address, uint16_t port )
{
    if( m_socket_fd == -1 )
        create_socket();

    int so_reuse = 1;
    int res = ::setsockopt( m_socket_fd, SOL_SOCKET, SO_REUSEADDR, &so_reuse, sizeof( so_reuse ));
    if( res == -1 )
        throw std::system_error(errno, std::system_category(), "set reuse addr failed" );

    sockaddr_in6 socket_addr{};
    std::fill( reinterpret_cast<char*>(&socket_addr)
               , reinterpret_cast<char*>(&socket_addr)+sizeof(socket_addr), 0 );
    socket_addr.sin6_family = AF_INET6;
    socket_addr.sin6_addr   = in6addr_loopback;
    socket_addr.sin6_port   = htobe16( port );

    if( ip_address == nullptr )
        throw std::invalid_argument( "bind() got nullptr for ip_address" );
    res = inet_pton( AF_INET6, ip_address, reinterpret_cast<void*>(&socket_addr.sin6_addr.s6_addr));
    if( res <= 0 )
    {
        throw std::system_error(errno, std::system_category()
                                , std::string( "failed inet_pton in bind() for " ) + ip_address );
    }

    if( ::bind( m_socket_fd, (struct sockaddr*)&socket_addr, sizeof( struct sockaddr_in6 )) == -1 )
        throw std::system_error( errno, std::system_category(), "bind failed" );
}

void TcpSocket::listen( Poller& poller )
{
    if( ::listen( m_socket_fd, 1024 ) == -1 )
        throw std::system_error(errno, std::system_category(), "listen failed" );

    m_poller_cb->writer_coro_handle = nullptr;
    m_poller_cb->reader_coro_handle = nullptr;
    poller.add_socket( *this, m_poller_cb, EPOLLIN );
}

TcpSocket TcpSocket::accept( sockaddr_in6& peer_addr )
{
    socklen_t peer_addr_size = sizeof( struct sockaddr_in6 );

    int client_fd = ::accept( m_socket_fd, (struct sockaddr*)&peer_addr, &peer_addr_size );
    if( client_fd == -1 )
        throw std::system_error(errno, std::system_category(), "accept failed" );

    return TcpSocket( client_fd );
}

ssize_t TcpSocket::read( char* buff, size_t buff_size )
{
    ssize_t read_size = ::recv( m_socket_fd, buff, buff_size, 0 );
    if( read_size == -1 )
        throw std::system_error(errno, std::system_category(), "socket read failed" );

    return read_size;
}

ssize_t TcpSocket::write( const char* buff, size_t buff_size )
{
    ssize_t wrote_size = ::send( m_socket_fd, buff, buff_size, MSG_NOSIGNAL );
    if( wrote_size == -1 )
        throw std::system_error(errno, std::system_category(), "socket write failed" );

    return wrote_size;
}

void TcpSocket::close()
{
    if( m_socket_fd == -1 )
        return;

    ::close( m_socket_fd );
    m_socket_fd = -1;

    m_poller_cb->clean();
    PollerCb::rm_reference( m_poller_cb );
    m_poller_cb = nullptr;
}

void TcpSocket::shutdown( int how )
{
    int res = ::shutdown( m_socket_fd, how );
    if( res == -1 )
        throw std::system_error( errno, std::system_category(), "shutdown failed" );
}

TcpSocket::~TcpSocket() noexcept
{
    close();
}

int TcpSocket::fd() const
{
    return m_socket_fd;
}

ssize_t TcpSocket::ReadVAwaiter::read_socket()
{
    struct msghdr msg = { nullptr, 0,
            m_iov, m_iovcnt, nullptr, 0, MSG_DONTWAIT };
    while( true )
    {
        ssize_t bytes_read = ::recvmsg( m_socket_fd, &msg, MSG_DONTWAIT );

        if( bytes_read == -1 )
        {
            if( errno == EAGAIN || errno == EWOULDBLOCK )
            {
                m_poller_cb.reset_bits( EPOLLIN );
                return 0;
            }
            if( errno == EINTR )
                continue;

            throw std::system_error( errno, std::system_category()
                                     ,std::string("failed read in read_socket: ")
                                     + strerror( errno ) );
        }
        if( static_cast<size_t>(bytes_read) < m_total_size )
            m_poller_cb.reset_bits( EPOLLIN );

        return bytes_read;
    }
}

auto TcpSocket::ready_read()
{
    struct Awaiter
    {
        PollerCb& poller_cb;

        static bool await_ready() {return false;}
        void await_suspend( std::experimental::coroutine_handle<> coro_handle )
        { poller_cb.reader_coro_handle = coro_handle; }
        void await_resume() { poller_cb.reader_coro_handle = nullptr; }
    };
    return Awaiter{*m_poller_cb};
}
auto TcpSocket::poll_write_event()
{
    struct Awaiter
    {
        PollerCb& poller_cb;

        static bool await_ready() { return false; }
        void await_suspend( std::experimental::coroutine_handle<> coro_handle )
        { poller_cb.writer_coro_handle = coro_handle; }
        void await_resume() { poller_cb.writer_coro_handle = nullptr; }
    };
    return Awaiter{*m_poller_cb};
}

CoroutineAwaiter<ssize_t> TcpSocket::try_async_read( void* buffer, uint32_t buffer_size )
{
    ssize_t bytes_read = 0;
    while( true )
    {
#if defined(USE_IO_URING)
        bytes_read = co_await NetUring::instance().async_read( m_socket_fd, buffer, buffer_size );
#else
        ssize_t bytes_read = ::recv( m_socket_fd, buffer, buffer_size, MSG_DONTWAIT );
        if( bytes_read == -1 )
            bytes_read = -errno;
#endif
        if( bytes_read == -EINTR )
            continue;
        break;
    }
    if( bytes_read < buffer_size )
        m_poller_cb->reset_bits( EPOLLIN );

    co_return bytes_read;
}

CoroutineAwaiter<ssize_t> TcpSocket::async_read(
        void* buffer, uint32_t buffer_size, uint32_t min_threshold )
{
    assert( buffer_size >= min_threshold );

    uint32_t total_read = 0;
    // if read get less bytes then asked, EPOLLIN will be reset
    // but if previous read got exactly asked bytes, socket will be empty,
    // but EPOLLIN will be set
    if( m_poller_cb->events_mask & EPOLLIN )
    { // previous read probably did not get all data, so will try to read
        ssize_t bytes_read = co_await try_async_read( buffer, buffer_size );
        // 0 means socket was actually empty so we need to epoll
        // -1 or >0 means error or some data read
        if( bytes_read > 0 )
            total_read = bytes_read;
        else if( bytes_read < 0 )
            if( bytes_read == -EAGAIN || bytes_read == -EWOULDBLOCK )
                total_read = 0;
            else
                throw std::system_error(
                        -bytes_read, std::system_category()
                        ,std::string("failed TcpSocket::async_read(): ")
                         +strerror( -bytes_read ) );
        else // bytes_read == 0
            co_return 0;
    }
    while( total_read < min_threshold )
    {
        co_await ready_read();
        ssize_t bytes_read = co_await try_async_read( (uint8_t*)buffer+total_read
                                                      , buffer_size-total_read );
        if( bytes_read > 0 )
            total_read += bytes_read;
        else if( bytes_read < 0 )
            if( bytes_read == -EAGAIN || bytes_read == -EWOULDBLOCK )
                continue;
            else
                throw std::system_error(
                        -bytes_read, std::system_category()
                        ,std::string("failed TcpSocket::async_read() in while: ")
                         +strerror( -bytes_read ) );
        else // bytes_read == 0
            break;
    }
    co_return total_read;
}

CoroutineAwaiter<ssize_t> TcpSocket::try_async_write( const void* buffer, size_t buffer_size )
{
#if defined(USE_IO_URING)
    ssize_t bytes_wrote = co_await NetUring::instance().async_write( m_socket_fd, buffer, buffer_size );
#else
    ssize_t bytes_wrote = ::send( m_socket_fd, buffer, buffer_size, MSG_DONTWAIT|MSG_NOSIGNAL );
    if( bytes_wrote == -1 )
        bytes_wrote = -errno;
#endif
    if( bytes_wrote < 0 )
    {
        if( bytes_wrote == EAGAIN || errno == EWOULDBLOCK )
            m_poller_cb->reset_bits( EPOLLOUT );
        else
            throw std::system_error(
                    errno, std::system_category()
                    ,std::string("failed NetUring::instance().try_async_write: ")
                     +strerror( -bytes_wrote ) );
    }
    if( bytes_wrote > 0 && static_cast<size_t>(bytes_wrote) < buffer_size )
        m_poller_cb->reset_bits( EPOLLOUT );

    co_return bytes_wrote;
}
CoroutineAwaiter<ssize_t> TcpSocket::async_write( const void* buffer, uint32_t buffer_size )
{   // if last write sent less bytes then asked, EPOLLOUT will be reset
    // but if previous write send bytes equal to send buffer size, buffer will be full,
    // but EPOLLOUT will be set
    while( true )
    {
        if( m_poller_cb->events_mask & EPOLLOUT
            && !(m_poller_cb->events_mask & EPOLLHUP) )
        { // previous write probably did not fill buffer, so will try to send
            ssize_t bytes_wrote = co_await try_async_write( buffer, buffer_size );

            // 0 means buffer filled so we need to epoll
            // -1 or >0 means error or some data wrote, so we do not need to epoll
            if( bytes_wrote >= 0 )
                co_return bytes_wrote;
            // FIXME: write error handling here
        }
        co_await poll_write_event();
    }
}

CoroutineAwaiter<int> TcpSocket::try_async_accept( sockaddr_in6* peer_addr )
{
    while( true )
    {
        socklen_t addrlen = sizeof( sockaddr_in6 );
        int accepted_fd = ::accept4(
                m_socket_fd
                , reinterpret_cast<sockaddr*>(peer_addr)
                , (peer_addr==nullptr)?nullptr:&addrlen
                , SOCK_NONBLOCK | SOCK_CLOEXEC );
        if( accepted_fd == -1 )
        {
            if( errno == EAGAIN || errno == EWOULDBLOCK )
            {
                m_poller_cb->reset_bits( EPOLLIN );
                co_return accepted_fd;
            }
            if( errno == EINTR )
                continue;

            m_poller_cb->reset_bits( EPOLLIN );
            throw std::system_error(errno, std::system_category(),
                    "failed accept in try_async_accept" );
        }

        co_return accepted_fd;
    }
}
CoroutineAwaiter<TcpSocket> TcpSocket::async_accept( Poller& poller, sockaddr_in6* peer_addr )
{
    if( m_poller_cb->events_mask & EPOLLIN )
    { // if previous accept() got last socket, EPOLLIN will be set but next accept() will fail
        int accepted_fd = co_await try_async_accept( peer_addr );
        if( accepted_fd >= 0 )
            co_return TcpSocket{ accepted_fd, &poller };
    }
    co_await ready_read();
    int accepted_fd = co_await try_async_accept( peer_addr );

    co_return TcpSocket{ accepted_fd, &poller };
}

CoroutineAwaiter<bool> TcpSocket::async_connect( Poller& poller, const sockaddr_in6* peer_addr )
{
    m_poller_cb->writer_coro_handle = nullptr;
    m_poller_cb->reader_coro_handle = nullptr;
    poller.add_socket( *this, m_poller_cb );

    while( true )
    {
        int res = ::connect( m_socket_fd, reinterpret_cast<const sockaddr*>(peer_addr)
                             ,sizeof(sockaddr_in6) );
        if( res == -1 )
        {
            if( errno == EINPROGRESS )
            {
                co_await poll_write_event();

                int error = 0;
                socklen_t error_len = sizeof(error);
                getsockopt( m_socket_fd, SOL_SOCKET, SO_ERROR, &error, &error_len );
                if( !error )
                    co_return true;

                errno = error;
                co_return false;
            }
            if( errno == EINTR )
                continue;

            co_return false;
        }
        co_return true;
    }
}
CoroutineAwaiter<bool> TcpSocket::async_connect( Poller& poller, const char* hostname, uint16_t port )
{
    PeerResolver resolver( hostname );

    if( !resolver )
        throw std::runtime_error(
                std::string( "hostname \"" ) + hostname + "\"resolution failed: "+resolver.error_str() );

    while( resolver )
    {
        const sockaddr_in6& peer_addr = resolver.sockaddr( port );
        bool  connected = co_await async_connect( poller, &peer_addr );
        if( connected )
            co_return true;
        resolver.next();
    }
    co_return false;
}

}
