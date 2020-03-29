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

#include <libcornet/poller.hpp>

#include <unistd.h>
#include <cstdio>
#include <string>
#include <array>
#include <algorithm>
#include <system_error>

#include <libcornet/tcp_socket.hpp>
#include <libcornet/async_file.hpp>
#include <libcornet/net_uring.hpp>

namespace pioneer19::cornet {

Poller::Poller()
{
    m_poller_fd = epoll_create1( EPOLL_CLOEXEC );
    if( m_poller_fd == -1 )
    {
        throw std::system_error(errno, std::system_category()
                                , "failed epoll_create1() in Poller constructor" );
    }
}

Poller::Poller( Poller&& other ) noexcept
{
    m_poller_fd = other.m_poller_fd;
    other.m_poller_fd = -1;
}

Poller& Poller::operator=( Poller&& other ) noexcept
{
    if( this != &other )
    {
        close();
        std::swap( m_poller_fd, other.m_poller_fd );
    }
    return *this;
}

void Poller::close()
{
    if( m_poller_fd != -1 )
        ::close( m_poller_fd );

    m_poller_fd = -1;
}

void Poller::run()
{
    int timeout_ms = -1; // -1 is infinite timeout for epoll_wait

    while( true)
    {
        constexpr uint32_t EVENT_BATCH_SIZE = 16;
        epoll_event events[ EVENT_BATCH_SIZE ];
        if( m_stop )
            break;
        int res = epoll_wait( m_poller_fd, events, EVENT_BATCH_SIZE, timeout_ms );
        timeout_ms = -1;
        if( m_stop )
            break;
        if( res == -1 )
        {
            if( errno == EINTR )
                continue;

            throw std::system_error(errno, std::system_category()
                                    , std::string( "failed epoll_wait on epoll socket " )
                                      + std::to_string( m_poller_fd ));
        }

        for( uint32_t i = 0; i < static_cast<uint32_t>(res); ++i )
        {
            auto& curr_event = events[i];
            auto* poller_cb = reinterpret_cast<PollerCb*>(curr_event.data.ptr);
//            printf( "epoll_wait for poller_cb %p got events %s\n"
//                    , (void*)poller_cb, events_string( curr_event.events ).c_str() );
            poller_cb->events_mask = curr_event.events;
            poller_cb->m_backlink = &curr_event;
        }
        /*
         * poller_cb->m_backlink  references curr_event
         * current_event.data.ptr references poller_cb
         * current_event is local data, poller_cb is socket's data
         * poller_cb can be removed with socket in any coro.resume() call
         */
        for( uint32_t i = 0; i < static_cast<uint32_t>(res); ++i )
        {
            auto& curr_event = events[i];
            // curr_event.data.ptr will be nullptr in case poller_cb removed
            // in previous event processing
            if( curr_event.data.ptr == nullptr )
                continue;
            auto poller_cb = reinterpret_cast<PollerCb*>(curr_event.data.ptr);
            if( (curr_event.events & EPOLLOUT)
                && poller_cb->writer_coro_handle )
            {
                poller_cb->writer_coro_handle.resume();
            }
            // curr_event.data.ptr will be nullptr in case poller_cb removed
            // in previous event processing or in writer_coro_handle.resume()
            if( curr_event.data.ptr == nullptr )
                continue;
            if( (curr_event.events & EPOLLIN)
                && poller_cb->reader_coro_handle )
            {
                poller_cb->reader_coro_handle.resume();
            }
            // can be nullptr in case poller_cb removed
            if( curr_event.data.ptr != nullptr )
                poller_cb->m_backlink = nullptr;
        }
#if defined(USE_IO_URING)
        uint32_t queue_size = NetUring::instance().process_requests();
        if( queue_size != 0 )
            timeout_ms = 0;
#endif
    }
}

int Poller::add_fd( int fd, PollerCb* poller_cb, uint32_t mask )
{
    epoll_event event = {};
    event.events = mask;
    event.data.ptr = poller_cb;
    return epoll_ctl( m_poller_fd, EPOLL_CTL_ADD, fd, &event);
}

void Poller::add_socket( const TcpSocket& socket, PollerCb* poller_cb, uint32_t mask )
{
    if( add_fd( socket.fd(), poller_cb, mask ) == -1 )
    {
        throw std::system_error(errno, std::system_category()
                                , std::string( "failed epoll_ctl add socket " )
                                + std::to_string(socket.fd()) );
    }
}

void Poller::add_file( const AsyncFile& async_file, PollerCb* poller_cb, uint32_t mask )
{
    if( add_fd( async_file.fd(), poller_cb, mask ) == -1 )
    {
        throw std::system_error(errno, std::system_category()
                                , std::string( "failed epoll_ctl add async file " )
                                  + std::to_string(async_file.fd()) );
    }
}


std::string Poller::events_string( uint32_t events_mask )
{
    constexpr std::array<uint32_t,10> event_types =
            {EPOLLIN, EPOLLOUT, EPOLLRDHUP, EPOLLPRI, EPOLLERR, EPOLLHUP, EPOLLET
             ,EPOLLONESHOT, EPOLLWAKEUP, EPOLLEXCLUSIVE };
    constexpr std::array<const char*,10>  event_print_types =
            { "IN", "OUT", "RDHUP", "PRI", "ERR", "HUP", "ET"
              ,"ONESHOT", "WAKEUP", "EXCLUSIVE" };
    static_assert( event_types.size() == event_print_types.size()
                   , "event_types.size != event_print_types.size" );

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

void Poller::run_on_signal( int signum, std::function<void()> func )
{
    if( !m_signal_processor )
        m_signal_processor = std::make_unique<SignalProcessor>( *this );

    m_signal_processor->add_signal_handler( signum, std::move(func) );
}

}
