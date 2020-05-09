/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
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
            poller_cb->add_reference();
            poller_cb->events_mask = curr_event.events;
        }
        /*
         * current_event.data.ptr - pointer to poller_cb.
         * to eliminate removing poller_cb with socket delete until poller not
         * finished it's processing, poller holds reference to poller_cb
         * (in this case poller_cb will be cleared, but not removed)
         */
        for( uint32_t i = 0; i < static_cast<uint32_t>(res); ++i )
        {
            auto& curr_event = events[i];
            if( curr_event.data.ptr == nullptr )
                continue;
            auto poller_cb = reinterpret_cast<PollerCb*>( curr_event.data.ptr );
            poller_cb->process_event();

            PollerCb::rm_reference( poller_cb );
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
