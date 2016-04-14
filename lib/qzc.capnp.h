#ifndef CAPN_C7BBE66A583460D4
#define CAPN_C7BBE66A583460D4
/* AUTO GENERATED - DO NOT EDIT */
#include <capn.h>

#if CAPN_VERSION != 1
#error "version mismatch between capn.h and generated code"
#endif


#ifdef __cplusplus
extern "C" {
#endif

struct QZCNodeInfoReq;
struct QZCNodeInfoRep;
struct QZCWKNResolveReq;
struct QZCWKNResolveRep;
struct QZCGetReq;
struct QZCGetRep;
struct QZCCreateReq;
struct QZCCreateRep;
struct QZCSetReq;
struct QZCDelReq;
struct QZCRequest;
struct QZCReply;
struct QZCNodeList;

typedef struct {capn_ptr p;} QZCNodeInfoReq_ptr;
typedef struct {capn_ptr p;} QZCNodeInfoRep_ptr;
typedef struct {capn_ptr p;} QZCWKNResolveReq_ptr;
typedef struct {capn_ptr p;} QZCWKNResolveRep_ptr;
typedef struct {capn_ptr p;} QZCGetReq_ptr;
typedef struct {capn_ptr p;} QZCGetRep_ptr;
typedef struct {capn_ptr p;} QZCCreateReq_ptr;
typedef struct {capn_ptr p;} QZCCreateRep_ptr;
typedef struct {capn_ptr p;} QZCSetReq_ptr;
typedef struct {capn_ptr p;} QZCDelReq_ptr;
typedef struct {capn_ptr p;} QZCRequest_ptr;
typedef struct {capn_ptr p;} QZCReply_ptr;
typedef struct {capn_ptr p;} QZCNodeList_ptr;

typedef struct {capn_ptr p;} QZCNodeInfoReq_list;
typedef struct {capn_ptr p;} QZCNodeInfoRep_list;
typedef struct {capn_ptr p;} QZCWKNResolveReq_list;
typedef struct {capn_ptr p;} QZCWKNResolveRep_list;
typedef struct {capn_ptr p;} QZCGetReq_list;
typedef struct {capn_ptr p;} QZCGetRep_list;
typedef struct {capn_ptr p;} QZCCreateReq_list;
typedef struct {capn_ptr p;} QZCCreateRep_list;
typedef struct {capn_ptr p;} QZCSetReq_list;
typedef struct {capn_ptr p;} QZCDelReq_list;
typedef struct {capn_ptr p;} QZCRequest_list;
typedef struct {capn_ptr p;} QZCReply_list;
typedef struct {capn_ptr p;} QZCNodeList_list;

struct QZCNodeInfoReq {
	uint64_t nid;
};

struct QZCNodeInfoRep {
	uint64_t nid;
	uint64_t tid;
};

struct QZCWKNResolveReq {
	uint64_t wid;
};

struct QZCWKNResolveRep {
	uint64_t wid;
	uint64_t nid;
};

struct QZCGetReq {
	uint64_t nid;
	uint64_t elem;
	uint64_t ctxtype;
	capn_ptr ctxdata;
	uint64_t itertype;
	capn_ptr iterdata;
};

struct QZCGetRep {
	uint64_t nid;
	uint64_t elem;
	uint64_t datatype;
	capn_ptr data;
	uint64_t itertype;
	capn_ptr nextiter;
};

struct QZCCreateReq {
	uint64_t parentnid;
	uint64_t parentelem;
	uint64_t datatype;
	capn_ptr data;
};

struct QZCCreateRep {
	uint64_t newnid;
};

struct QZCSetReq {
	uint64_t nid;
	uint64_t elem;
	uint64_t ctxtype;
	capn_ptr ctxdata;
	uint64_t datatype;
	capn_ptr data;
};

struct QZCDelReq {
	uint64_t nid;
};
enum QZCRequest_which {
	QZCRequest_ping = 0,
	QZCRequest_nodeinforeq = 1,
	QZCRequest_wknresolve = 2,
	QZCRequest_get = 3,
	QZCRequest_create = 4,
	QZCRequest_set = 5,
	QZCRequest_del = 6,
	QZCRequest_unset = 7
};

struct QZCRequest {
	enum QZCRequest_which which;
	union {
		QZCNodeInfoReq_ptr nodeinforeq;
		QZCWKNResolveReq_ptr wknresolve;
		QZCGetReq_ptr get;
		QZCCreateReq_ptr create;
		QZCSetReq_ptr set;
		QZCDelReq_ptr del;
		QZCSetReq_ptr unset;
	};
};
enum QZCReply_which {
	QZCReply_pong = 0,
	QZCReply_nodeinforep = 1,
	QZCReply_wknresolve = 2,
	QZCReply_get = 3,
	QZCReply_create = 4,
	QZCReply_set = 5,
	QZCReply_del = 6,
	QZCReply_unset = 7
};

struct QZCReply {
	unsigned error : 1;
	enum QZCReply_which which;
	union {
		QZCNodeInfoRep_ptr nodeinforep;
		QZCWKNResolveRep_ptr wknresolve;
		QZCGetRep_ptr get;
		QZCCreateRep_ptr create;
	};
};

struct QZCNodeList {
	capn_list64 nodes;
};

QZCNodeInfoReq_ptr new_QZCNodeInfoReq(struct capn_segment*);
QZCNodeInfoRep_ptr new_QZCNodeInfoRep(struct capn_segment*);
QZCWKNResolveReq_ptr new_QZCWKNResolveReq(struct capn_segment*);
QZCWKNResolveRep_ptr new_QZCWKNResolveRep(struct capn_segment*);
QZCGetReq_ptr new_QZCGetReq(struct capn_segment*);
QZCGetRep_ptr new_QZCGetRep(struct capn_segment*);
QZCCreateReq_ptr new_QZCCreateReq(struct capn_segment*);
QZCCreateRep_ptr new_QZCCreateRep(struct capn_segment*);
QZCSetReq_ptr new_QZCSetReq(struct capn_segment*);
QZCDelReq_ptr new_QZCDelReq(struct capn_segment*);
QZCRequest_ptr new_QZCRequest(struct capn_segment*);
QZCReply_ptr new_QZCReply(struct capn_segment*);
QZCNodeList_ptr new_QZCNodeList(struct capn_segment*);

QZCNodeInfoReq_list new_QZCNodeInfoReq_list(struct capn_segment*, int len);
QZCNodeInfoRep_list new_QZCNodeInfoRep_list(struct capn_segment*, int len);
QZCWKNResolveReq_list new_QZCWKNResolveReq_list(struct capn_segment*, int len);
QZCWKNResolveRep_list new_QZCWKNResolveRep_list(struct capn_segment*, int len);
QZCGetReq_list new_QZCGetReq_list(struct capn_segment*, int len);
QZCGetRep_list new_QZCGetRep_list(struct capn_segment*, int len);
QZCCreateReq_list new_QZCCreateReq_list(struct capn_segment*, int len);
QZCCreateRep_list new_QZCCreateRep_list(struct capn_segment*, int len);
QZCSetReq_list new_QZCSetReq_list(struct capn_segment*, int len);
QZCDelReq_list new_QZCDelReq_list(struct capn_segment*, int len);
QZCRequest_list new_QZCRequest_list(struct capn_segment*, int len);
QZCReply_list new_QZCReply_list(struct capn_segment*, int len);
QZCNodeList_list new_QZCNodeList_list(struct capn_segment*, int len);

void read_QZCNodeInfoReq(struct QZCNodeInfoReq*, QZCNodeInfoReq_ptr);
void read_QZCNodeInfoRep(struct QZCNodeInfoRep*, QZCNodeInfoRep_ptr);
void read_QZCWKNResolveReq(struct QZCWKNResolveReq*, QZCWKNResolveReq_ptr);
void read_QZCWKNResolveRep(struct QZCWKNResolveRep*, QZCWKNResolveRep_ptr);
void read_QZCGetReq(struct QZCGetReq*, QZCGetReq_ptr);
void read_QZCGetRep(struct QZCGetRep*, QZCGetRep_ptr);
void read_QZCCreateReq(struct QZCCreateReq*, QZCCreateReq_ptr);
void read_QZCCreateRep(struct QZCCreateRep*, QZCCreateRep_ptr);
void read_QZCSetReq(struct QZCSetReq*, QZCSetReq_ptr);
void read_QZCDelReq(struct QZCDelReq*, QZCDelReq_ptr);
void read_QZCRequest(struct QZCRequest*, QZCRequest_ptr);
void read_QZCReply(struct QZCReply*, QZCReply_ptr);
void read_QZCNodeList(struct QZCNodeList*, QZCNodeList_ptr);

void write_QZCNodeInfoReq(const struct QZCNodeInfoReq*, QZCNodeInfoReq_ptr);
void write_QZCNodeInfoRep(const struct QZCNodeInfoRep*, QZCNodeInfoRep_ptr);
void write_QZCWKNResolveReq(const struct QZCWKNResolveReq*, QZCWKNResolveReq_ptr);
void write_QZCWKNResolveRep(const struct QZCWKNResolveRep*, QZCWKNResolveRep_ptr);
void write_QZCGetReq(const struct QZCGetReq*, QZCGetReq_ptr);
void write_QZCGetRep(const struct QZCGetRep*, QZCGetRep_ptr);
void write_QZCCreateReq(const struct QZCCreateReq*, QZCCreateReq_ptr);
void write_QZCCreateRep(const struct QZCCreateRep*, QZCCreateRep_ptr);
void write_QZCSetReq(const struct QZCSetReq*, QZCSetReq_ptr);
void write_QZCDelReq(const struct QZCDelReq*, QZCDelReq_ptr);
void write_QZCRequest(const struct QZCRequest*, QZCRequest_ptr);
void write_QZCReply(const struct QZCReply*, QZCReply_ptr);
void write_QZCNodeList(const struct QZCNodeList*, QZCNodeList_ptr);

void get_QZCNodeInfoReq(struct QZCNodeInfoReq*, QZCNodeInfoReq_list, int i);
void get_QZCNodeInfoRep(struct QZCNodeInfoRep*, QZCNodeInfoRep_list, int i);
void get_QZCWKNResolveReq(struct QZCWKNResolveReq*, QZCWKNResolveReq_list, int i);
void get_QZCWKNResolveRep(struct QZCWKNResolveRep*, QZCWKNResolveRep_list, int i);
void get_QZCGetReq(struct QZCGetReq*, QZCGetReq_list, int i);
void get_QZCGetRep(struct QZCGetRep*, QZCGetRep_list, int i);
void get_QZCCreateReq(struct QZCCreateReq*, QZCCreateReq_list, int i);
void get_QZCCreateRep(struct QZCCreateRep*, QZCCreateRep_list, int i);
void get_QZCSetReq(struct QZCSetReq*, QZCSetReq_list, int i);
void get_QZCDelReq(struct QZCDelReq*, QZCDelReq_list, int i);
void get_QZCRequest(struct QZCRequest*, QZCRequest_list, int i);
void get_QZCReply(struct QZCReply*, QZCReply_list, int i);
void get_QZCNodeList(struct QZCNodeList*, QZCNodeList_list, int i);

void set_QZCNodeInfoReq(const struct QZCNodeInfoReq*, QZCNodeInfoReq_list, int i);
void set_QZCNodeInfoRep(const struct QZCNodeInfoRep*, QZCNodeInfoRep_list, int i);
void set_QZCWKNResolveReq(const struct QZCWKNResolveReq*, QZCWKNResolveReq_list, int i);
void set_QZCWKNResolveRep(const struct QZCWKNResolveRep*, QZCWKNResolveRep_list, int i);
void set_QZCGetReq(const struct QZCGetReq*, QZCGetReq_list, int i);
void set_QZCGetRep(const struct QZCGetRep*, QZCGetRep_list, int i);
void set_QZCCreateReq(const struct QZCCreateReq*, QZCCreateReq_list, int i);
void set_QZCCreateRep(const struct QZCCreateRep*, QZCCreateRep_list, int i);
void set_QZCSetReq(const struct QZCSetReq*, QZCSetReq_list, int i);
void set_QZCDelReq(const struct QZCDelReq*, QZCDelReq_list, int i);
void set_QZCRequest(const struct QZCRequest*, QZCRequest_list, int i);
void set_QZCReply(const struct QZCReply*, QZCReply_list, int i);
void set_QZCNodeList(const struct QZCNodeList*, QZCNodeList_list, int i);

#ifdef __cplusplus
}
#endif
#endif
