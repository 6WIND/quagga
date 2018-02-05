/*
 * Copyright (C) 2018 6WIND
 */
#ifndef _QUAGGA_BFD_CAPNP_H
#define _QUAGGA_BFD_CAPNP_H

#include "zebra.h"
#include "bfdd.h"
capn_ptr qcapn_new_BFD(struct capn_segment *s);
void qcapn_BFD_read(struct bfd *s, capn_ptr p);
void qcapn_BFD_write(const struct bfd *s, capn_ptr p);
#endif /* _QUAGGA_BFD_CAPNP_H */
