/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <iostream>

#include <libcornet/tls/parser.hpp>
namespace record = pioneer19::cornet::tls13::record;

#include "client_hello_record.hpp"
#include "server_hello_record.hpp"

int main()
{
    auto err = record::print_net_record( tls13_client_hello_record
                                         ,sizeof( tls13_client_hello_record ) );
//    auto err = record::print_net_record( reinterpret_cast<const char*>(tls13_server_hello_record)
//                                         ,sizeof( tls13_server_hello_record ) );

    if( err )
        std::cout << "error: " << err.message() << "\n";

    return 0;
}
