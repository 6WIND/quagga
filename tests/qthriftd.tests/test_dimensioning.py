#!/usr/bin/env python

import os, sys, argparse, traceback, signal, time
import logging

import thriftpy, thriftpy.rpc
from thriftpy.transport import TBufferedTransportFactory, TTransportException

vpnsvc_thrift = thriftpy.load("vpnservice.thrift", module_name="vpnsvc_thrift")

class NonzeroReturn(Exception):
    pass

class NonzeroWrap(object):
    def __init__(self, obj, errs = {}):
        self._obj = obj
        self._errs = errs
    def __getattr__(self, name):
        attr = getattr(self._obj, name)
        if not callable(attr):
            return attr
        def zero_exc(*args, **kwargs):
            ret = attr(*args, **kwargs)
            if not (isinstance(ret, int) or isinstance(ret, long)):
                return ret
            if ret != 0:
                raise NonzeroReturn('function %s() returned %d (%s)' % (
                    name, ret, self._errs.get(ret, 'unknown')))
            return ret
        return zero_exc

class BGPUpdImpl(object):
    def __getattr__(self, name):
        def not_impl(*args):
            sys.stderr.write('received call %s(%s)\n' % (
                name,
                ', '.join([repr(i) for i in args]),
                ))
        return not_impl

class NoTimeoutTransport(TBufferedTransportFactory):
    def get_transport(self, client):
        client.socket_timeout = None
        client.sock.settimeout(None)
        return super(NoTimeoutTransport, self).get_transport(client)

def run(addr, port):
    errs = dict([(v, k) for (k, v) in vpnsvc_thrift.__dict__.items() if k.startswith('BGP_ERR_')])
    client = NonzeroWrap(thriftpy.rpc.make_client(vpnsvc_thrift.BgpConfigurator, addr, port), errs)

    try:
        print client.startBgp(64603, '10.125.0.1', 179, 30, 60, 60, False)
    except:
        traceback.print_exc()

    as_base=65000
    vrf_base='1111'
    vrf=''
    asnumber=0
    for i in range(1, 1000):
        asnumber=as_base+i
        vrf = str(asnumber)+':'+vrf_base
        client.addVrf(vrf, [vrf], [vrf])
    client.enableGracefulRestart(60)
    time.sleep(1)
    
    ip_base=2
    for i in range(ip_base, 10):
        ip='10.125.0.'+str(i)
        asnumber=as_base+i
        client.createPeer(ip, asnumber)
        client.enableAddressFamily(ip,
            vpnsvc_thrift.af_afi.AFI_IP, vpnsvc_thrift.af_safi.SAFI_MPLS_VPN)
        client.setEbgpMultihop('10.125.0.2', 130)
    
    for i in range (1, 10):
        asnumber=as_base + i
        vrf = str(asnumber)+':'+vrf_base
        for j in range (1, 30000):
            ip1=10+10*i
            ip2=j%254
            ip_net = str(ip1)+'.'+str(ip2)+'.0.0/24'
            ip_nh = '10.11.0.15'
            client.pushRoute(ip_net, ip_nh, vrf, 200)

    time.sleep(1)
    more = True
    time.sleep(1)
    arg = vpnsvc_thrift.GET_RTS_INIT
    while more:
        routes = client.getRoutes(arg, 96 * 2)
        print repr(routes)
        more = routes.more > 0
        arg = vpnsvc_thrift.GET_RTS_NEXT

    time.sleep(1)


def run_reverse():
    server = thriftpy.rpc.make_server(
            vpnsvc_thrift.BgpUpdater,
            BGPUpdImpl(),
            '0.0.0.0', 6644,
            trans_factory = NoTimeoutTransport())
    server.serve()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
            format='%(asctime)s %(levelname)s %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S')

    argp = argparse.ArgumentParser(description = "VPNService Thrift<>Cap'n'Proto test client")
    argp.add_argument('--thrift-connaddr', type = str, default = '127.0.0.1')
    argp.add_argument('--thrift-connport', type = int, default = 7644)
    args = argp.parse_args()

    pid = os.fork()
    if pid == 0:
        run_reverse()
    else:
        try:
            run(args.thrift_connaddr, args.thrift_connport)
        finally:
            os.kill(pid, signal.SIGTERM)

