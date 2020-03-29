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

#include <sys/epoll.h>

#include <cstdint>
#include <memory>
#include <system_error>

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

    int fd() const;

    std::unique_ptr<PollerCb> m_poller_cb;
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
    return ReadAwaiter{ *(m_poller_cb.get()), m_fd, buff, buff_size };
}

}
