/* qthrift thrift BGP Configurator Server Part
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
#ifndef _QTHRIFT_BGP_CONFIGURATOR_H
#define _QTHRIFT_BGP_CONFIGURATOR_H

G_BEGIN_DECLS

void qthrift_bgp_configurator_server_terminate(void);

#define TYPE_INSTANCE_BGP_CONFIGURATOR_HANDLER \
  (instance_bgp_configurator_handler_get_type())

#define INSTANCE_BGP_CONFIGURATOR_HANDLER(obj)  \
  (G_TYPE_CHECK_INSTANCE_CAST ((obj),     \
    TYPE_BGP_CONFIGURATOR_HANDLER,\
    InstanceBgpConfiguratorHandler))

#define INSTANCE_BGP_CONFIGURATOR_HANDLER_CLASS(c) \
  (G_TYPE_CHECK_CLASS_CAST ((c),             \
    TYPE_INSTANCE_BGP_CONFIGURATOR_HANDLER,   \
     InstanceBgpConfiguratorHandlerClass))

#define IS_INSTANCE_BGP_CONFIGURATOR_HANDLER(obj)  \
  (G_TYPE_CHECK_INSTANCE_TYPE ((obj),        \
    TYPE_INSTANCE_BGP_CONFIGURATOR_HANDLER))

#define IS_INSTANCE_BGP_CONFIGURATOR_HANDLER_CLASS(c)  \
  (G_TYPE_CHECK_CLASS_TYPE ((c),                 \
    TYPE_INSTANCE_BGP_CONFIGURATOR_HANDLER))

#define INSTANCE_BGP_CONFIGURATOR_HANDLER_GET_CLASS(obj)   \
  (G_TYPE_INSTANCE_GET_CLASS ((obj),                 \
    TYPE_INSTANCE_BGP_CONFIGURATOR_HANDLER, \
    InstanceBgpConfiguratorHandlerClass))

struct _InstanceBgpConfiguratorHandler {
  BgpConfiguratorHandler parent_instance;
};
typedef struct _InstanceBgpConfiguratorHandler InstanceBgpConfiguratorHandler;
  
struct _InstanceBgpConfiguratorHandlerClass {
  BgpConfiguratorHandlerClass parent_class;
};
typedef struct _InstanceBgpConfiguratorHandlerClass InstanceBgpConfiguratorHandlerClass;

GType instance_bgp_configurator_handler_get_type (void);

G_END_DECLS

#endif /*  _QTHRIFT_BGP_CONFIGURATOR_H */
