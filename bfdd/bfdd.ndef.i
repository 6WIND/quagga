/*
 * Copyright (C) 2018 6WIND
 */

static void
_qzc_set_bfd_1(struct bfd *p, struct QZCSetReq *req,
               struct capn_segment *seg)
{
  if (req->ctxtype != 0)
      /* error */
      return;

  if (req->datatype != 0xfd0316f1800aebfd)
      /* error */
      return;

  qcapn_BFD_set(p, req->data);
}

/* [3dd958b139b0bfdd] bfdd <> bfd */
static void
_qzc_set_bfd(void *entity, struct QZCSetReq *req, struct QZCSetRep *rep,
             struct capn_segment *seg)
{
    struct bfd *p;
    int ret = 1;

    p = (struct bfd *)entity;
    rep->data = new_QZCSetRepReturnCode(seg);
    write_QZCSetRepReturnCode (ret, rep->data);
    switch (req->elem) {
    case 1:
        _qzc_set_bfd_1(p, req, seg);
        return;
    default:
        return;
    }
}

struct qzc_nodetype qzc_t_bfd = {
	.tid = 0x3dd958b139b0bfdd,
	.node_member_offset = (ptrdiff_t)offsetof(struct bfd, qzc_node),
	.set = _qzc_set_bfd,
};
/* WKN 37b64fdb20888a51 */
static uint64_t _wknresolve_37b64fdb20888a51(void)
{
    struct bfd *elem = bfd;
    if (!elem)
        return 0;
    return elem->qzc_node.nid;
}
static struct qzc_wkn _wkn_37b64fdb20888a51 = {
    .wid = 0x37b64fdb20888a51,
    .resolve = _wknresolve_37b64fdb20888a51,
};
static void _wkninit_37b64fdb20888a51(void) __attribute__ ((constructor));
static void _wkninit_37b64fdb20888a51(void)
{
    qzc_wkn_reg(&_wkn_37b64fdb20888a51);
};
