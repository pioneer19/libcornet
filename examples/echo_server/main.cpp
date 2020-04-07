/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <cstring>
#include <unistd.h>
#include <system_error>
#include <iostream>

#include <echo_server/echo_server.hpp>
#include <libcornet/poller.hpp>
namespace net = pioneer19::cornet;

int main()
{
    std::cout << "Polling echo server (single thread)\n";

    net::Poller poller;

    EchoServer echo_server{ poller };
    echo_server.run();

    poller.run_on_signal( SIGINT, [&echo_server,&poller](){ echo_server.stop(); poller.stop();} );
    poller.run_on_signal( SIGHUP, [&echo_server,&poller](){ echo_server.stop(); poller.stop();} );
    //poller.run_on_signal( SIGINT, [](){puts("SIGQUIT");} );
    poller.run();

    return 0;
}
