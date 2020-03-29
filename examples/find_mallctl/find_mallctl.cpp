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
