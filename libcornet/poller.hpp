/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
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

    static std::string events_string( uint32_t events_mask );

private:
    int add_fd( int fd, PollerCb* poller_cb
            ,uint32_t mask = EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLPRI|EPOLLET );
    void close();

    int m_poller_fd = -1;
    bool m_stop = false;
    std::unique_ptr<SignalProcessor> m_signal_processor;
};

}
