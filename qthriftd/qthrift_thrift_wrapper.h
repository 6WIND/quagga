/* qthrift thrift Wrapper 
 * Copyright (c) 2016 6WIND,
 *
 * This file is part of GNU Quagga.
 *
 * GNU Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#ifndef _QTHRIFT_THRIFT_WRAPPER_H
#define _QTHRIFT_THRIFT_WRAPPER_H

#include <thrift/c_glib/thrift.h>
#include <thrift/c_glib/protocol/thrift_binary_protocol_factory.h>
#include <thrift/c_glib/server/thrift_simple_server.h>
#include <thrift/c_glib/transport/thrift_buffered_transport.h>
#include <thrift/c_glib/transport/thrift_buffered_transport_factory.h>
#include <thrift/c_glib/transport/thrift_framed_transport.h>
#include <thrift/c_glib/protocol/thrift_binary_protocol.h>
#include <thrift/c_glib/transport/thrift_server_socket.h>
#include <thrift/c_glib/transport/thrift_socket.h>

extern ThriftTransport *thrift_server_socket_accept (ThriftServerTransport *transport, GError **error);
extern gboolean thrift_server_socket_listen (ThriftServerTransport *transport, GError **error);
extern gboolean thrift_server_socket_close (ThriftServerTransport *transport, GError **error);
extern gboolean thrift_buffered_transport_close (ThriftTransport *transport, GError **error);

#if defined(PACKAGE)
#undef PACKAGE
#endif
#if defined(PACKAGE_TARNAME)
#undef PACKAGE_TARNAME
#endif
#if defined(PACKAGE_VERSION)
#undef PACKAGE_VERSION
#endif
#if defined(PACKAGE_STRING)
#undef PACKAGE_STRING
#endif
#if defined(PACKAGE_BUGREPORT)
#undef PACKAGE_BUGREPORT
#endif
#if defined(PACKAGE_NAME)
#undef PACKAGE_NAME
#endif
#if defined(VERSION)
#undef VERSION
#endif

#endif /* _QTHRIFT_THRIFT_WRAPPER_H */
