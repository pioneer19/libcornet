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

#include <unordered_map>
#include <functional>
#include <experimental/coroutine>

#include <libcornet/async_file.hpp>

namespace pioneer19::cornet
{

class SignalProcessor
{
public:
    explicit SignalProcessor( Poller& poller );

    void add_signal_handler( int signum, std::function<void()> func );

private:
    struct SignalRunner
    {
        struct promise_type;
        using coro_handler = std::experimental::coroutine_handle<promise_type>;

        struct promise_type
        {
            std::experimental::suspend_never initial_suspend() { return {}; }
            std::experimental::suspend_never final_suspend()   { return {}; }
            SignalRunner get_return_object()
            {
                return SignalRunner{coro_handler::from_promise(*this)};
            }
            void unhandled_exception() { std::terminate(); }
            void return_void() {}
        };

        SignalRunner() = default;
        explicit SignalRunner( coro_handler coro ) noexcept
            :coro( coro )
        {}
        SignalRunner( SignalRunner&& other ) noexcept
            : coro(std::move(other.coro) ){ other.coro = nullptr; }
        SignalRunner& operator=( SignalRunner&& other ) noexcept
        { if( this != &other) { std::swap( coro, other.coro); } return *this; }

        SignalRunner( const SignalRunner& ) = delete;
        SignalRunner& operator=( const SignalRunner& ) = delete;
        ~SignalRunner() { if( coro ) coro.destroy(); }

        coro_handler coro;
    };

    using HandlersMap = std::unordered_map<int,std::function<void()>>;

    SignalRunner create_signal_runner( AsyncFile& m_async_file, const HandlersMap& m_signal_handlers );

    AsyncFile m_async_file;
    HandlersMap  m_signal_handlers;
    SignalRunner m_runner;
};

}
