/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once

namespace pioneer19::cornet
{

struct PRODUCTION_OS_SEAM
{
    static int printf( const char*, ... ) { return 0; }

    static int debug_printf( const char*, ... ) { return 0; }
//    static void print( const char* c_str ) { ::printf( "%s", c_str ); }
};

}
