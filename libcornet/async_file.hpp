/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once

#include <sys/epoll.h>
#include <unistd.h>

#include <cstddef>
#include <system_error>
#include <experimental/coroutine>

#include <libcornet/poller_cb.hpp>

namespace pioneer19::cornet
{

class Poller;

class AsyncFile
{
public:
    struct ReadAwaiter
    {
        bool await_ready();
        void await_suspend(std::experimental::coroutine_handle<>);
        ssize_t await_resume();

        ReadAwaiter( PollerCb& poller_cb, int fd, char* buff, size_t buff_size )
                :m_poller_cb( poller_cb )
                ,m_fd( fd )
                ,m_buff{ buff }
                ,m_buff_size{ buff_size }
        {}
        ssize_t read_file();

        PollerCb& m_poller_cb;
        int     m_fd = -1;
        char*   m_buff;
        size_t  m_buff_size;
        ssize_t m_bytes_read = -1;
    };

    AsyncFile() = default;
    explicit AsyncFile( int fd, Poller* poller = nullptr );
    AsyncFile( AsyncFile&& ) noexcept;
    AsyncFile& operator=( AsyncFile&& ) noexcept;
    ~AsyncFile() noexcept;

    AsyncFile( const AsyncFile& ) = delete;
    AsyncFile& operator=( const AsyncFile& ) = delete;

    ssize_t read( char* buff, size_t buff_size );
    AsyncFile::ReadAwaiter async_read( char* buff, size_t buff_size );

    void close();

private:
    friend class Poller;
    friend class SignalProcessor;

    [[nodiscard]]
    int fd() const;

    PollerCb* m_poller_cb = nullptr;
    int m_fd = -1;
};

inline bool AsyncFile::ReadAwaiter::await_ready()
{
    if( m_poller_cb.events_mask & EPOLLIN )
        return (m_bytes_read = read_file()) >= 0;
    else
        return false;
}

inline void AsyncFile::ReadAwaiter::await_suspend( std::experimental::coroutine_handle<> coro_handle )
{
    m_poller_cb.reader_coro_handle = coro_handle;
}

inline ssize_t AsyncFile::ReadAwaiter::await_resume()
{
    m_poller_cb.reader_coro_handle = nullptr;
    if( m_bytes_read == -1 )
        m_bytes_read = read_file();

    return m_bytes_read;
}

inline AsyncFile::ReadAwaiter AsyncFile::async_read( char* buff, size_t buff_size )
{
    return ReadAwaiter{ *m_poller_cb, m_fd, buff, buff_size };
}

}
