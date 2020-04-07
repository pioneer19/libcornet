/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <unistd.h>
#include <iostream>

#include <tls_client/tls_client.hpp>
#include <libcornet/poller.hpp>
namespace net = pioneer19::cornet;

int main()
{
    std::cout << "Polling TLS client (single thread)\n";

    net::Poller poller;

    TlsClient tls_client{ poller };
    tls_client.run();

    poller.run_on_signal( SIGINT, [&tls_client,&poller](){ tls_client.stop(); poller.stop();} );
    poller.run_on_signal( SIGHUP, [&tls_client,&poller](){ tls_client.stop(); poller.stop();} );

    poller.run();

    return 0;
}
