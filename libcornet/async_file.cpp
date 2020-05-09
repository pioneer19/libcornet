/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <libcornet/async_file.hpp>

#include <unistd.h>

#include <memory>
#include <system_error>

#include <libcornet/poller.hpp>

namespace pioneer19::cornet
{

AsyncFile::AsyncFile( AsyncFile&& other ) noexcept
    :m_poller_cb( other.m_poller_cb )
    ,m_fd( other.m_fd )
{
    other.m_poller_cb = nullptr;
    other.m_fd = -1;
}

AsyncFile& AsyncFile::operator=( AsyncFile&& other ) noexcept
{
    if( this != &other )
    {
        close();
        std::swap( m_fd, other.m_fd );
        std::swap( m_poller_cb, other.m_poller_cb );
    }
    return *this;
}

AsyncFile::AsyncFile( int fd, Poller* poller )
    :m_poller_cb( new PollerCb )
    ,m_fd( fd )
{
    if( poller )
        poller->add_file( *this, m_poller_cb, EPOLLIN );
}

ssize_t AsyncFile::read( char* buff, size_t buff_size )
{
    ssize_t read_size = ::read( m_fd, buff, buff_size );
    if( read_size == -1 )
        throw std::system_error(errno, std::system_category(), "file read failed" );

    return read_size;
}

void AsyncFile::close()
{
    if( m_fd == -1 )
        return;

    ::close( m_fd );
    m_fd = -1;

    m_poller_cb->clean();
    PollerCb::rm_reference( m_poller_cb );
    m_poller_cb = nullptr;
}

AsyncFile::~AsyncFile() noexcept
{
    close();
}

int AsyncFile::fd() const
{
    return m_fd;
}

ssize_t AsyncFile::ReadAwaiter::read_file()
{
    while( true )
    {
        ssize_t bytes_read = ::read( m_fd, m_buff, m_buff_size );

        if( bytes_read < 0
            || ( bytes_read >= 0 && static_cast<size_t>(bytes_read) < m_buff_size ) )
        {
            m_poller_cb.reset_bits( EPOLLIN );
        }
        if( bytes_read >= 0 )
            return bytes_read;

        if( bytes_read == -1 )
        {
            if( errno == EAGAIN || errno == EWOULDBLOCK )
                return bytes_read;
            if( errno == EINTR )
                continue;

            throw std::system_error( errno, std::system_category(), "failed read in await_ready" );
        }

        return bytes_read;
    }
}

}
