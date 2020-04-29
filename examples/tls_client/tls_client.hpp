/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once

#include <experimental/coroutine>

#include <libcornet/tcp_socket.hpp>
#include <pioneer19_utils/promise_list.hpp>

struct TlsServerRunner
{
    struct promise_type;
    using coro_handler = std::experimental::coroutine_handle<promise_type>;

    struct promise_type
    {
        std::experimental::suspend_never  initial_suspend() { return {}; }
        std::experimental::suspend_always final_suspend()   { return {}; }
        TlsServerRunner get_return_object()
        {
            return TlsServerRunner{coro_handler::from_promise(*this) };
        }
        void unhandled_exception() { std::terminate(); }
        void return_void() {}
    };

    TlsServerRunner() = default;
    explicit TlsServerRunner( coro_handler coro ) noexcept
        :coro( coro )
    {}
    TlsServerRunner( TlsServerRunner&& other ) noexcept
        : coro(std::move(other.coro) ){ other.coro = nullptr; }
    TlsServerRunner& operator=( TlsServerRunner&& other ) noexcept
    { if( this != &other) { std::swap( coro, other.coro); } return *this; }
    ~TlsServerRunner() { stop(); }

    TlsServerRunner( const TlsServerRunner& ) = delete;
    TlsServerRunner& operator=( const TlsServerRunner& ) = delete;

    void stop() { if( coro ) { coro.destroy(); coro = nullptr; } }

    coro_handler coro;
};

namespace pioneer19::cornet
{
class Poller;
}

class TlsClient
{
public:
    explicit TlsClient( pioneer19::cornet::Poller& poller );
    TlsClient( const TlsClient& ) = delete;
    TlsClient( TlsClient&& ) = delete;
    TlsClient& operator=( const TlsClient& ) = delete;
    TlsClient& operator=( TlsClient&& ) = delete;

    void run();
    void stop() { m_runner.stop(); }

private:
    TlsServerRunner create_runner();

    pioneer19::cornet::Poller& m_poller;
    TlsServerRunner m_runner;
};

inline void TlsClient::run()
{
    if( m_runner.coro )
        return;

    m_runner = create_runner();
}

// TlsClientSession create_tls_session( pioneer19::cornet::TcpSocket tcp_socket );
// size_t create_tls_handshake( char* buff, size_t size );
