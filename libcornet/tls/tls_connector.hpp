/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once

#include <libcornet/tls/tls_connector_template.hpp>
#include <libcornet/production_seams.hpp>

namespace pioneer19::cornet::tls13
{

using TlsConnector = TlsConnectorImpl<PRODUCTION_OS_SEAM>;

}
