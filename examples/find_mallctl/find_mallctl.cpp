/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <dlfcn.h>

#include <cstdio>
#include <cstdlib>

int main()
{
    dlerror();    /* Clear any existing error */
    // dlsym can return nullptr if no such symbol or if symbol contains nullptr.
    // In case symbol not found dlerror will return non empty error string
    // this is not important in my case but I still hold that dlerror() call

    void* symbol = dlsym( RTLD_DEFAULT, "mallctl" );
    printf( "mallctl address 0x%p\n", symbol );
    char* error = dlerror();
    if( symbol == nullptr || error )
    {
        printf("error in dlsym: %s\n", error);
        exit(EXIT_FAILURE);
    }

    using MallCtlFunc = int (*)(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
    auto* mallctl = reinterpret_cast<MallCtlFunc>( symbol );
    int res = mallctl( "thread.tcache.flush", nullptr, nullptr, nullptr, 0 );
    if( res != 0 )
        printf("got error in mallctl");

    exit(EXIT_SUCCESS);
}
