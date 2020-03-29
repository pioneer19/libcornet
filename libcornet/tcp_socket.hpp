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

#pragma once

#include <netinet/in.h>
#include <sys/uio.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <system_error>

#include <libcornet/poller.hpp>
#include <libcornet/coroutines_utils.hpp>

#include <libcornet/config.hpp>
#include <libcornet/net_uring.hpp>

namespace pioneer19::cornet
{
class TcpSocket
{
public:
    struct ReadVAwaiter;

    TcpSocket();
    TcpSocket( TcpSocket&& ) noexcept;
    TcpSocket& operator=( TcpSocket&& ) noexcept;
    ~TcpSocket() noexcept;

    TcpSocket( const TcpSocket& ) = delete;
    TcpSocket& operator=( const TcpSocket& ) = delete;

    /**
     *
     * @param ip_address "2a00:1450:4010:c09::64" or "::FFFF:94.100.180.199"
     * @param port
     */
    void bind( const char* ip_address, uint16_t port );
    void listen( Poller& );

    TcpSocket accept( sockaddr_in6& peer_addr );
    TcpSocket connect( sockaddr_in6& peer_addr );
    ssize_t read( char* buff, size_t buff_size );
    ssize_t write( const char* buff, size_t buff_size );

    coroutines::CoroutineAwaiter<TcpSocket> async_accept( Poller& poller, sockaddr_in6* peer_addr );
    [[nodiscard]]
    coroutines::CoroutineAwaiter<bool> async_connect( Poller& poller, const sockaddr_in6* peer_addr );
    [[nodiscard]]
    coroutines::CoroutineAwaiter<bool> async_connect( Poller& poller, const char* hostname, uint16_t port );

    coroutines::CoroutineAwaiter<ssize_t> async_read( void* buffer, uint32_t buffer_size );
    coroutines::CoroutineAwaiter<ssize_t> async_write( const void* buffer, uint32_t buffer_size );
    TcpSocket::ReadVAwaiter async_readv( iovec *iov, uint32_t iovcnt );

    void close();
    void shutdown( int how = SHUT_RDWR );

private:
    friend class Poller;

    explicit TcpSocket( int socket_fd, Poller* poller = nullptr );
    void create_socket();
    [[nodiscard]]
    int fd() const;
    /**
     * co_await ready_read() will wait for socket become readable
     * @return Awaiter for co_await
     */
    auto ready_read();
    /**
     * co_await poll_write_event() will wait for socket get EPOLLOUT
     * @return Awaiter for co_await
     */
    auto poll_write_event();
    coroutines::CoroutineAwaiter<int>     try_async_accept(  sockaddr_in6* peer_addr );
    coroutines::CoroutineAwaiter<ssize_t> try_async_read(  void* buffer, size_t buffer_size );
    coroutines::CoroutineAwaiter<ssize_t> try_async_write( const void* buffer, size_t buffer_size );

    std::unique_ptr<PollerCb> m_poller_cb;
    int m_socket_fd = -1;
};

struct TcpSocket::ReadVAwaiter
{
    bool await_ready();
    void await_suspend(std::experimental::coroutine_handle<>);
    ssize_t await_resume();

    ReadVAwaiter( PollerCb& poller_cb, int socket_fd, iovec *iov, uint32_t iovcnt )
            :m_poller_cb( poller_cb )
             ,m_socket_fd( socket_fd )
             ,m_iovcnt{ iovcnt }
             ,m_iov{ iov }
    {
        for( unsigned i = 0; i < m_iovcnt; ++i )
        {
            m_total_size += m_iov[i].iov_len;
        }
    }

private:
    ssize_t read_socket();

    PollerCb& m_poller_cb;
    int     m_socket_fd = -1;
    uint32_t m_iovcnt;
    iovec*  m_iov;
    uint32_t m_total_size = 0;
    ssize_t m_bytes_read = 0;
};

inline bool TcpSocket::ReadVAwaiter::await_ready()
{
    // if read get less bytes then asked, EPOLLIN will be reset
    // but if previous read got exactly asked bytes, socket will be empty,
    // but EPOLLIN will be set
    if( m_poller_cb.events_mask & EPOLLIN )
    { // previous read probably did not get all data, so will try to read
        m_bytes_read = read_socket();

        // 0 means socket was actually empty so we need to epoll
        // -1 or >0 means error or some data read, so we do not need to epoll
        return m_bytes_read;
    }

    return false;
}

inline void TcpSocket::ReadVAwaiter::await_suspend( std::experimental::coroutine_handle<> coro_handle )
{
    m_poller_cb.reader_coro_handle = coro_handle;
}

inline ssize_t TcpSocket::ReadVAwaiter::await_resume()
{
    m_poller_cb.reader_coro_handle = nullptr;
    if( m_bytes_read == 0 )
        m_bytes_read = read_socket();

    return m_bytes_read;
}

inline TcpSocket::ReadVAwaiter TcpSocket::async_readv( iovec *iov, uint32_t iovcnt )
{
    return ReadVAwaiter{*m_poller_cb, m_socket_fd, iov, iovcnt };
}

}
