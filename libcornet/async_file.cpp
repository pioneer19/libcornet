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

#include <libcornet/async_file.hpp>

#include <unistd.h>

#include <memory>
#include <system_error>

#include <experimental/coroutine>

#include <libcornet/poller.hpp>

namespace pioneer19::cornet
{

AsyncFile::AsyncFile( AsyncFile&& other ) noexcept
    :m_poller_cb( other.m_poller_cb.release() )
    ,m_fd( other.m_fd )
{
    other.m_fd = -1;
}

AsyncFile& AsyncFile::operator=( AsyncFile&& other ) noexcept
{
    if( this != &other )
    {
        close();
        std::swap( m_fd, other.m_fd );
        m_poller_cb.swap( other.m_poller_cb );
    }
    return *this;
}

AsyncFile::AsyncFile( int fd, Poller* poller )
    :m_poller_cb( new PollerCb )
    ,m_fd( fd )
{
    if( poller )
        poller->add_file( *this, m_poller_cb.get(), EPOLLIN );
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

    Poller::clear_backlink( m_poller_cb->m_backlink );
    m_poller_cb.reset( nullptr );
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
