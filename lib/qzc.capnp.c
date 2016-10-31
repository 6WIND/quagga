#include "qzc.capnp.h"
/* AUTO GENERATED - DO NOT EDIT */

QZCNodeInfoReq_ptr new_QZCNodeInfoReq(struct capn_segment *s) {
	QZCNodeInfoReq_ptr p;
	p.p = capn_new_struct(s, 8, 0);
	return p;
}
QZCNodeInfoReq_list new_QZCNodeInfoReq_list(struct capn_segment *s, int len) {
	QZCNodeInfoReq_list p;
	p.p = capn_new_list(s, len, 8, 0);
	return p;
}
void read_QZCNodeInfoReq(struct QZCNodeInfoReq *s, QZCNodeInfoReq_ptr p) {
	capn_resolve(&p.p);
	s->nid = capn_read64(p.p, 0);
}
void write_QZCNodeInfoReq(const struct QZCNodeInfoReq *s, QZCNodeInfoReq_ptr p) {
	capn_resolve(&p.p);
	capn_write64(p.p, 0, s->nid);
}
void get_QZCNodeInfoReq(struct QZCNodeInfoReq *s, QZCNodeInfoReq_list l, int i) {
	QZCNodeInfoReq_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_QZCNodeInfoReq(s, p);
}
void set_QZCNodeInfoReq(const struct QZCNodeInfoReq *s, QZCNodeInfoReq_list l, int i) {
	QZCNodeInfoReq_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_QZCNodeInfoReq(s, p);
}

QZCNodeInfoRep_ptr new_QZCNodeInfoRep(struct capn_segment *s) {
	QZCNodeInfoRep_ptr p;
	p.p = capn_new_struct(s, 16, 0);
	return p;
}
QZCNodeInfoRep_list new_QZCNodeInfoRep_list(struct capn_segment *s, int len) {
	QZCNodeInfoRep_list p;
	p.p = capn_new_list(s, len, 16, 0);
	return p;
}
void read_QZCNodeInfoRep(struct QZCNodeInfoRep *s, QZCNodeInfoRep_ptr p) {
	capn_resolve(&p.p);
	s->nid = capn_read64(p.p, 0);
	s->tid = capn_read64(p.p, 8);
}
void write_QZCNodeInfoRep(const struct QZCNodeInfoRep *s, QZCNodeInfoRep_ptr p) {
	capn_resolve(&p.p);
	capn_write64(p.p, 0, s->nid);
	capn_write64(p.p, 8, s->tid);
}
void get_QZCNodeInfoRep(struct QZCNodeInfoRep *s, QZCNodeInfoRep_list l, int i) {
	QZCNodeInfoRep_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_QZCNodeInfoRep(s, p);
}
void set_QZCNodeInfoRep(const struct QZCNodeInfoRep *s, QZCNodeInfoRep_list l, int i) {
	QZCNodeInfoRep_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_QZCNodeInfoRep(s, p);
}

QZCWKNResolveReq_ptr new_QZCWKNResolveReq(struct capn_segment *s) {
	QZCWKNResolveReq_ptr p;
	p.p = capn_new_struct(s, 8, 0);
	return p;
}
QZCWKNResolveReq_list new_QZCWKNResolveReq_list(struct capn_segment *s, int len) {
	QZCWKNResolveReq_list p;
	p.p = capn_new_list(s, len, 8, 0);
	return p;
}
void read_QZCWKNResolveReq(struct QZCWKNResolveReq *s, QZCWKNResolveReq_ptr p) {
	capn_resolve(&p.p);
	s->wid = capn_read64(p.p, 0);
}
void write_QZCWKNResolveReq(const struct QZCWKNResolveReq *s, QZCWKNResolveReq_ptr p) {
	capn_resolve(&p.p);
	capn_write64(p.p, 0, s->wid);
}
void get_QZCWKNResolveReq(struct QZCWKNResolveReq *s, QZCWKNResolveReq_list l, int i) {
	QZCWKNResolveReq_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_QZCWKNResolveReq(s, p);
}
void set_QZCWKNResolveReq(const struct QZCWKNResolveReq *s, QZCWKNResolveReq_list l, int i) {
	QZCWKNResolveReq_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_QZCWKNResolveReq(s, p);
}

QZCWKNResolveRep_ptr new_QZCWKNResolveRep(struct capn_segment *s) {
	QZCWKNResolveRep_ptr p;
	p.p = capn_new_struct(s, 16, 0);
	return p;
}
QZCWKNResolveRep_list new_QZCWKNResolveRep_list(struct capn_segment *s, int len) {
	QZCWKNResolveRep_list p;
	p.p = capn_new_list(s, len, 16, 0);
	return p;
}
void read_QZCWKNResolveRep(struct QZCWKNResolveRep *s, QZCWKNResolveRep_ptr p) {
	capn_resolve(&p.p);
	s->wid = capn_read64(p.p, 0);
	s->nid = capn_read64(p.p, 8);
}
void write_QZCWKNResolveRep(const struct QZCWKNResolveRep *s, QZCWKNResolveRep_ptr p) {
	capn_resolve(&p.p);
	capn_write64(p.p, 0, s->wid);
	capn_write64(p.p, 8, s->nid);
}
void get_QZCWKNResolveRep(struct QZCWKNResolveRep *s, QZCWKNResolveRep_list l, int i) {
	QZCWKNResolveRep_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_QZCWKNResolveRep(s, p);
}
void set_QZCWKNResolveRep(const struct QZCWKNResolveRep *s, QZCWKNResolveRep_list l, int i) {
	QZCWKNResolveRep_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_QZCWKNResolveRep(s, p);
}

QZCGetReq_ptr new_QZCGetReq(struct capn_segment *s) {
	QZCGetReq_ptr p;
	p.p = capn_new_struct(s, 32, 2);
	return p;
}
QZCGetReq_list new_QZCGetReq_list(struct capn_segment *s, int len) {
	QZCGetReq_list p;
	p.p = capn_new_list(s, len, 32, 2);
	return p;
}
void read_QZCGetReq(struct QZCGetReq *s, QZCGetReq_ptr p) {
	capn_resolve(&p.p);
	s->nid = capn_read64(p.p, 0);
	s->elem = capn_read64(p.p, 8);
	s->ctxtype = capn_read64(p.p, 16);
	s->ctxdata = capn_getp(p.p, 0, 0);
	s->itertype = capn_read64(p.p, 24);
	s->iterdata = capn_getp(p.p, 1, 0);
}
void write_QZCGetReq(const struct QZCGetReq *s, QZCGetReq_ptr p) {
	capn_resolve(&p.p);
	capn_write64(p.p, 0, s->nid);
	capn_write64(p.p, 8, s->elem);
	capn_write64(p.p, 16, s->ctxtype);
	capn_setp(p.p, 0, s->ctxdata);
	capn_write64(p.p, 24, s->itertype);
	capn_setp(p.p, 1, s->iterdata);
}
void get_QZCGetReq(struct QZCGetReq *s, QZCGetReq_list l, int i) {
	QZCGetReq_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_QZCGetReq(s, p);
}
void set_QZCGetReq(const struct QZCGetReq *s, QZCGetReq_list l, int i) {
	QZCGetReq_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_QZCGetReq(s, p);
}

QZCGetRep_ptr new_QZCGetRep(struct capn_segment *s) {
	QZCGetRep_ptr p;
	p.p = capn_new_struct(s, 32, 2);
	return p;
}
QZCGetRep_list new_QZCGetRep_list(struct capn_segment *s, int len) {
	QZCGetRep_list p;
	p.p = capn_new_list(s, len, 32, 2);
	return p;
}
void read_QZCGetRep(struct QZCGetRep *s, QZCGetRep_ptr p) {
	capn_resolve(&p.p);
	s->nid = capn_read64(p.p, 0);
	s->elem = capn_read64(p.p, 8);
	s->datatype = capn_read64(p.p, 16);
	s->data = capn_getp(p.p, 0, 0);
	s->itertype = capn_read64(p.p, 24);
	s->nextiter = capn_getp(p.p, 1, 0);
}
void write_QZCGetRep(const struct QZCGetRep *s, QZCGetRep_ptr p) {
	capn_resolve(&p.p);
	capn_write64(p.p, 0, s->nid);
	capn_write64(p.p, 8, s->elem);
	capn_write64(p.p, 16, s->datatype);
	capn_setp(p.p, 0, s->data);
	capn_write64(p.p, 24, s->itertype);
	capn_setp(p.p, 1, s->nextiter);
}
void get_QZCGetRep(struct QZCGetRep *s, QZCGetRep_list l, int i) {
	QZCGetRep_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_QZCGetRep(s, p);
}
void set_QZCGetRep(const struct QZCGetRep *s, QZCGetRep_list l, int i) {
	QZCGetRep_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_QZCGetRep(s, p);
}
QZCSetRep_ptr new_QZCSetRep(struct capn_segment *s) {
	QZCSetRep_ptr p;
	p.p = capn_new_struct(s, 24, 1);
	return p;
}
void write_QZCSetRep(const struct QZCSetRep *s, QZCSetRep_ptr p) {
	capn_resolve(&p.p);
	capn_write64(p.p, 0, s->nid);
	capn_write64(p.p, 8, s->elem);
	capn_write64(p.p, 16, s->datatype);
	capn_setp(p.p, 0, s->data);
}
void read_QZCSetRep(struct QZCSetRep *s, QZCSetRep_ptr p) {
	capn_resolve(&p.p);
	s->nid = capn_read64(p.p, 0);
	s->elem = capn_read64(p.p, 8);
	s->datatype = capn_read64(p.p, 16);
	s->data = capn_getp(p.p, 0, 0);
}
QZCCreateReq_ptr new_QZCCreateReq(struct capn_segment *s) {
	QZCCreateReq_ptr p;
	p.p = capn_new_struct(s, 24, 1);
	return p;
}
QZCCreateReq_list new_QZCCreateReq_list(struct capn_segment *s, int len) {
	QZCCreateReq_list p;
	p.p = capn_new_list(s, len, 24, 1);
	return p;
}
void read_QZCCreateReq(struct QZCCreateReq *s, QZCCreateReq_ptr p) {
	capn_resolve(&p.p);
	s->parentnid = capn_read64(p.p, 0);
	s->parentelem = capn_read64(p.p, 8);
	s->datatype = capn_read64(p.p, 16);
	s->data = capn_getp(p.p, 0, 0);
}
void write_QZCCreateReq(const struct QZCCreateReq *s, QZCCreateReq_ptr p) {
	capn_resolve(&p.p);
	capn_write64(p.p, 0, s->parentnid);
	capn_write64(p.p, 8, s->parentelem);
	capn_write64(p.p, 16, s->datatype);
	capn_setp(p.p, 0, s->data);
}
capn_ptr new_QZCSetRepReturnCode(struct capn_segment *s) {
  return capn_new_struct(s, 4, 0);
}
void write_QZCSetRepReturnCode(int s, capn_ptr p) {
  capn_resolve(&p);
  capn_write32(p, 0, s);
}
void read_QZCSetRepReturnCode(int *s, capn_ptr p) {
  capn_resolve(&p);
  *s = capn_read32(p, 0);
}
void get_QZCCreateReq(struct QZCCreateReq *s, QZCCreateReq_list l, int i) {
	QZCCreateReq_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_QZCCreateReq(s, p);
}
void set_QZCCreateReq(const struct QZCCreateReq *s, QZCCreateReq_list l, int i) {
	QZCCreateReq_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_QZCCreateReq(s, p);
}

QZCCreateRep_ptr new_QZCCreateRep(struct capn_segment *s) {
	QZCCreateRep_ptr p;
	p.p = capn_new_struct(s, 8, 0);
	return p;
}
QZCCreateRep_list new_QZCCreateRep_list(struct capn_segment *s, int len) {
	QZCCreateRep_list p;
	p.p = capn_new_list(s, len, 8, 0);
	return p;
}
void read_QZCCreateRep(struct QZCCreateRep *s, QZCCreateRep_ptr p) {
	capn_resolve(&p.p);
	s->newnid = capn_read64(p.p, 0);
}
void write_QZCCreateRep(const struct QZCCreateRep *s, QZCCreateRep_ptr p) {
	capn_resolve(&p.p);
	capn_write64(p.p, 0, s->newnid);
}
void get_QZCCreateRep(struct QZCCreateRep *s, QZCCreateRep_list l, int i) {
	QZCCreateRep_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_QZCCreateRep(s, p);
}
void set_QZCCreateRep(const struct QZCCreateRep *s, QZCCreateRep_list l, int i) {
	QZCCreateRep_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_QZCCreateRep(s, p);
}

QZCSetReq_ptr new_QZCSetReq(struct capn_segment *s) {
	QZCSetReq_ptr p;
	p.p = capn_new_struct(s, 32, 2);
	return p;
}
QZCSetReq_list new_QZCSetReq_list(struct capn_segment *s, int len) {
	QZCSetReq_list p;
	p.p = capn_new_list(s, len, 32, 2);
	return p;
}
void read_QZCSetReq(struct QZCSetReq *s, QZCSetReq_ptr p) {
	capn_resolve(&p.p);
	s->nid = capn_read64(p.p, 0);
	s->elem = capn_read64(p.p, 8);
	s->ctxtype = capn_read64(p.p, 16);
	s->ctxdata = capn_getp(p.p, 0, 0);
	s->datatype = capn_read64(p.p, 24);
	s->data = capn_getp(p.p, 1, 0);
}
void write_QZCSetReq(const struct QZCSetReq *s, QZCSetReq_ptr p) {
	capn_resolve(&p.p);
	capn_write64(p.p, 0, s->nid);
	capn_write64(p.p, 8, s->elem);
	capn_write64(p.p, 16, s->ctxtype);
	capn_setp(p.p, 0, s->ctxdata);
	capn_write64(p.p, 24, s->datatype);
	capn_setp(p.p, 1, s->data);
}
void get_QZCSetReq(struct QZCSetReq *s, QZCSetReq_list l, int i) {
	QZCSetReq_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_QZCSetReq(s, p);
}
void set_QZCSetReq(const struct QZCSetReq *s, QZCSetReq_list l, int i) {
	QZCSetReq_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_QZCSetReq(s, p);
}

QZCDelReq_ptr new_QZCDelReq(struct capn_segment *s) {
	QZCDelReq_ptr p;
	p.p = capn_new_struct(s, 8, 0);
	return p;
}
QZCDelReq_list new_QZCDelReq_list(struct capn_segment *s, int len) {
	QZCDelReq_list p;
	p.p = capn_new_list(s, len, 8, 0);
	return p;
}
void read_QZCDelReq(struct QZCDelReq *s, QZCDelReq_ptr p) {
	capn_resolve(&p.p);
	s->nid = capn_read64(p.p, 0);
}
void write_QZCDelReq(const struct QZCDelReq *s, QZCDelReq_ptr p) {
	capn_resolve(&p.p);
	capn_write64(p.p, 0, s->nid);
}
void get_QZCDelReq(struct QZCDelReq *s, QZCDelReq_list l, int i) {
	QZCDelReq_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_QZCDelReq(s, p);
}
void set_QZCDelReq(const struct QZCDelReq *s, QZCDelReq_list l, int i) {
	QZCDelReq_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_QZCDelReq(s, p);
}

QZCRequest_ptr new_QZCRequest(struct capn_segment *s) {
	QZCRequest_ptr p;
	p.p = capn_new_struct(s, 8, 1);
	return p;
}
QZCRequest_list new_QZCRequest_list(struct capn_segment *s, int len) {
	QZCRequest_list p;
	p.p = capn_new_list(s, len, 8, 1);
	return p;
}
void read_QZCRequest(struct QZCRequest *s, QZCRequest_ptr p) {
	capn_resolve(&p.p);
	s->which = (enum QZCRequest_which)(int) capn_read16(p.p, 0);
	switch (s->which) {
	case QZCRequest_nodeinforeq:
	case QZCRequest_wknresolve:
	case QZCRequest_get:
	case QZCRequest_create:
	case QZCRequest_set:
	case QZCRequest_del:
	case QZCRequest_unset:
		s->unset.p = capn_getp(p.p, 0, 0);
		break;
	default:
		break;
	}
}
void write_QZCRequest(const struct QZCRequest *s, QZCRequest_ptr p) {
	capn_resolve(&p.p);
	capn_write16(p.p, 0, s->which);
	switch (s->which) {
	case QZCRequest_nodeinforeq:
	case QZCRequest_wknresolve:
	case QZCRequest_get:
	case QZCRequest_create:
	case QZCRequest_set:
	case QZCRequest_del:
	case QZCRequest_unset:
		capn_setp(p.p, 0, s->unset.p);
		break;
	default:
		break;
	}
}
void get_QZCRequest(struct QZCRequest *s, QZCRequest_list l, int i) {
	QZCRequest_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_QZCRequest(s, p);
}
void set_QZCRequest(const struct QZCRequest *s, QZCRequest_list l, int i) {
	QZCRequest_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_QZCRequest(s, p);
}

QZCReply_ptr new_QZCReply(struct capn_segment *s) {
	QZCReply_ptr p;
	p.p = capn_new_struct(s, 8, 1);
	return p;
}
QZCReply_list new_QZCReply_list(struct capn_segment *s, int len) {
	QZCReply_list p;
	p.p = capn_new_list(s, len, 8, 1);
	return p;
}
void read_QZCReply(struct QZCReply *s, QZCReply_ptr p) {
	capn_resolve(&p.p);
	s->error = (capn_read8(p.p, 0) & 1) != 0;
	s->which = (enum QZCReply_which)(int) capn_read16(p.p, 2);
	switch (s->which) {
	case QZCReply_nodeinforep:
	case QZCReply_wknresolve:
	case QZCReply_get:
	case QZCReply_set:
	case QZCReply_create:
	case QZCReply_unset:
		s->create.p = capn_getp(p.p, 0, 0);
		break;
	default:
		break;
	}
}
void write_QZCReply(const struct QZCReply *s, QZCReply_ptr p) {
	capn_resolve(&p.p);
	capn_write1(p.p, 0, s->error != 0);
	capn_write16(p.p, 2, s->which);
	switch (s->which) {
	case QZCReply_nodeinforep:
	case QZCReply_wknresolve:
	case QZCReply_get:
	case QZCReply_set:
	case QZCReply_create:
	case QZCReply_unset:
		capn_setp(p.p, 0, s->create.p);
		break;
	default:
		break;
	}
}
void get_QZCReply(struct QZCReply *s, QZCReply_list l, int i) {
	QZCReply_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_QZCReply(s, p);
}
void set_QZCReply(const struct QZCReply *s, QZCReply_list l, int i) {
	QZCReply_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_QZCReply(s, p);
}

QZCNodeList_ptr new_QZCNodeList(struct capn_segment *s) {
	QZCNodeList_ptr p;
	p.p = capn_new_struct(s, 0, 1);
	return p;
}
QZCNodeList_list new_QZCNodeList_list(struct capn_segment *s, int len) {
	QZCNodeList_list p;
	p.p = capn_new_list(s, len, 0, 1);
	return p;
}
void read_QZCNodeList(struct QZCNodeList *s, QZCNodeList_ptr p) {
	capn_resolve(&p.p);
	s->nodes.p = capn_getp(p.p, 0, 0);
}
void write_QZCNodeList(const struct QZCNodeList *s, QZCNodeList_ptr p) {
	capn_resolve(&p.p);
	capn_setp(p.p, 0, s->nodes.p);
}
void get_QZCNodeList(struct QZCNodeList *s, QZCNodeList_list l, int i) {
	QZCNodeList_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_QZCNodeList(s, p);
}
void set_QZCNodeList(const struct QZCNodeList *s, QZCNodeList_list l, int i) {
	QZCNodeList_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_QZCNodeList(s, p);
}
