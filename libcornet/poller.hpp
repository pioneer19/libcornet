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
#include <csignal>
#include <cstdint>
#include <memory>
#include <functional>

#include <libcornet/signal_processor.hpp>
#include <libcornet/poller_cb.hpp>

namespace pioneer19::cornet
{
class TcpSocket;
class AsyncFile;

class Poller
{
public:
    Poller();
    Poller( Poller&& ) noexcept;
    Poller& operator=( Poller&& other ) noexcept;

    Poller( const Poller& ) = delete;
    Poller& operator=( const Poller& ) = delete;

    void run();
    void stop() noexcept { m_stop = true; }
    void run_on_signal( int signum, std::function<void()> func );
    void add_socket( const TcpSocket& socket, PollerCb* poller_cb
            ,uint32_t mask = EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLPRI|EPOLLET );
    void add_file( const AsyncFile& async_file, PollerCb* poller_cb
            ,uint32_t mask = EPOLLIN|EPOLLRDHUP|EPOLLPRI|EPOLLET );
    static void clear_backlink( void* backlink ) noexcept;

    static std::string events_string( uint32_t events_mask );

private:
    int add_fd( int fd, PollerCb* poller_cb
            ,uint32_t mask = EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLPRI|EPOLLET );
    void close();

    int m_poller_fd = -1;
    bool m_stop = false;
    std::unique_ptr<SignalProcessor> m_signal_processor;
};

inline void Poller::clear_backlink( void* backlink ) noexcept
{
    if( backlink == nullptr )
        return;

    auto* event = reinterpret_cast<epoll_event*>(backlink);
    auto poller_cb = reinterpret_cast<PollerCb*>(event->data.ptr);
    poller_cb->m_backlink = nullptr;
    event->data.ptr = nullptr;
}

}
