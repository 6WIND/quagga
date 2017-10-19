# Copyright 2017 6WIND
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# - Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#
# - Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the
#   distribution.
#
# - Neither the name of 6WIND S.A. nor the names of its
#   contributors may be used to endorse or promote products derived
#   from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.
set -eux
set +u

# There must be 5 parameters given by callers:
# $1 - "zrpc" or "quagga"
# $2 - the directory where files are installed
# $3 - working directory for packaging
# $4 - hostname, including distribution and version, such as "Ubuntu14.04"
# $5 - last git commit ID

INST_BIN_DIR=$2
HOST_NAME=$4
COMMITID=$5
PACKAGE_DEB="n"

quagga_copy_bin_files () {

    if [ -f $INST_BIN_DIR/opt/quagga/etc/bgpd.conf ]; then
        sed -i -- 's/zebra/sdncbgpc/g' $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
    else
        echo "hostname bgpd" > $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
        echo "password sdncbgpc" >> $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
        echo "service advanced-vty" >> $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
        echo "log stdout" >> $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
        echo "line vty" >> $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
        echo " exec-timeout 0 0 " >> $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
        echo "debug bgp " >> $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
        echo "debug bgp updates" >> $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
        echo "debug bgp events" >> $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
        echo "debug bgp fsm" >> $INST_BIN_DIR/opt/quagga/etc/bgpd.conf
    fi

    rm -rf $INST_BIN_DIR/../bin
    mkdir -p $INST_BIN_DIR/../bin

    pushd $INST_BIN_DIR
    find ./opt/quagga/lib -name *.so* | xargs tar cf - | tar xf - -C $INST_BIN_DIR/../bin
    find ./opt/quagga/lib -name *.a | xargs tar cf - | tar xf - -C $INST_BIN_DIR/../bin
    find ./opt/quagga/bin | xargs tar cf - | tar xf - -C $INST_BIN_DIR/../bin
    find ./opt/quagga/include | xargs tar cf - | tar xf - -C $INST_BIN_DIR/../bin
    find ./opt/quagga/etc/init.d | xargs tar cf - | tar xf - -C $INST_BIN_DIR/../bin

    tar cf - ./opt/quagga/etc/bgpd.conf | tar xf - -C $INST_BIN_DIR/../bin
    tar cf - ./opt/quagga/sbin | tar xf - -C $INST_BIN_DIR/../bin

    if [ -f ./usr/lib/systemd/system/qbgp.service ]; then
        tar cf - ./usr/lib/systemd/system/qbgp.service | tar xf - -C $INST_BIN_DIR/../bin
    fi
    if [ -f ./etc/sysconfig/qbgp ]; then
        tar cf - ./etc/sysconfig/qbgp | tar xf - -C $INST_BIN_DIR/../bin
    fi
    popd

    mkdir -p $INST_BIN_DIR/../bin/opt/quagga/var/log/quagga
    touch $INST_BIN_DIR/../bin/opt/quagga/var/log/quagga/qthriftd.init.log
    touch $INST_BIN_DIR/../bin/opt/quagga/var/log/quagga/.dummyqbgp
    mkdir -p $INST_BIN_DIR/../bin/opt/quagga/var/run/quagga
    touch $INST_BIN_DIR/../bin/opt/quagga/var/run/quagga/.dummyqbgp

    pushd $INST_BIN_DIR/../bin
    if [ $PACKAGE_DEB = "y" ]; then
       cd $INST_BIN_DIR/../bin
       find . \! -type d | cpio -o -H ustar -R 0:0 | tar -C $DEB_BIN_DIR -x
    fi
    popd
}

quagga_rpm_bin_spec () {

    echo "Name: quagga" >> $RPM_SPEC_FILE
    if [ -z "$COMMITID" ]; then
        echo "Version: 1.0.2.$HOST_NAME" >> $RPM_SPEC_FILE
    else
        echo "Version: 1.0.2.$COMMITID.$HOST_NAME" >> $RPM_SPEC_FILE
    fi
    echo "Release: 0" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "Summary: Quagga Routing Suite" >> $RPM_SPEC_FILE
    echo "Group: Applications/Internet" >> $RPM_SPEC_FILE
    echo "License: GPL" >> $RPM_SPEC_FILE

    echo "BuildRoot: $RPM_BIN_DIR/BUILD/ROOT" >> $RPM_SPEC_FILE
    case $HOST_NAME in
    RedHat7*)
        QBGP_RPM_DEPS="thrift zmq glib2"
        ;;
    SUSE*)
        QBGP_RPM_DEPS="thrift zmq glib2 libgobject-2_0-0"
        ;;
    CentOS*)
        QBGP_RPM_DEPS="thrift zmq"
        ;;
    esac
    echo "Requires: $QBGP_RPM_DEPS" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%description" >> $RPM_SPEC_FILE
    printf "Quagga is an advanced routing software package that provides a suite of TCP/IP based routing protocols.\n" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%install" >> $RPM_SPEC_FILE
    echo "rm -rf %{buildroot} && mkdir -p %{buildroot}" >> $RPM_SPEC_FILE
    echo "cd $INST_BIN_DIR/../bin && find . \! -type d | cpio -o -H ustar -R 0:0 | tar -C %{buildroot} -x" >> $RPM_SPEC_FILE
    echo "find %{buildroot} -type f -o -type l|sed "s,%{buildroot},," > %{_builddir}/files" >> $RPM_SPEC_FILE
    echo "sed -ri "s/\.py$/\.py*/" %{_builddir}/files" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%clean" >> $RPM_SPEC_FILE
    echo "rm -rf %{buildroot}" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%pre" >> $RPM_SPEC_FILE
    echo "getent group quagga >/dev/null 2>&1 || groupadd -g 92 quagga >/dev/null 2>&1 || :" >> $RPM_SPEC_FILE
    echo "getent passwd quagga >/dev/null 2>&1 || useradd -u 92 -g 92 -M -r -s /sbin/nologin \\" >> $RPM_SPEC_FILE
    echo " -d /var/run/quagga quagga >/dev/null 2>&1 || :" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%postun" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%post" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%preun" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%files -f %{_builddir}/files" >> $RPM_SPEC_FILE
    echo "%defattr(-,root,root)" >> $RPM_SPEC_FILE
    echo "%dir %attr(750,quagga,quagga) /opt/quagga/var/run/quagga" >> $RPM_SPEC_FILE
    echo "%dir %attr(750,quagga,quagga) /opt/quagga/var/log/quagga" >> $RPM_SPEC_FILE
}

quagga_deb_bin_control () {

    echo "Package: quagga" >> $DEB_CONTROL_FILE
    if [ -z "$COMMITID" ]; then
        echo "Version: 1.0.2.$HOST_NAME" >> $DEB_CONTROL_FILE
    else
        echo "Version: 1.0.2.$COMMITID.$HOST_NAME" >> $DEB_CONTROL_FILE
    fi
    echo "Architecture: amd64" >> $DEB_CONTROL_FILE
    echo "Maintainer: 6WIND <packaging@6wind.com>" >> $DEB_CONTROL_FILE
    echo "Depends: thrift(>=0.9), zmq(>=4.1.0), libglib2.0-0(>=2.22.5)" >> $DEB_CONTROL_FILE
    echo "Description: Quagga Routing Suite" >> $DEB_CONTROL_FILE
    printf " Quagga is an advanced routing software package that provides a suite of TCP/IP based routing protocols.\n" >> $DEB_CONTROL_FILE

    if [ -f $INST_BIN_DIR/preinst ]; then
        cp $INST_BIN_DIR/preinst $DEB_BIN_DIR/DEBIAN/
    fi

    printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/postinst
    printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/postinst
    printf 'if [ "$1" = "configure" ]; then\n' >> $DEB_BIN_DIR/DEBIAN/postinst
    printf '  :\n' >> $DEB_BIN_DIR/DEBIAN/postinst
    printf 'fi\n' >> $DEB_BIN_DIR/DEBIAN/postinst
    chmod a+x $DEB_BIN_DIR/DEBIAN/postinst

    printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/prerm
    printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/prerm
    chmod a+x $DEB_BIN_DIR/DEBIAN/prerm

    printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/postrm
    printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/postrm
    printf 'if [ "$1" = "remove" ]; then\n' >> $DEB_BIN_DIR/DEBIAN/postrm
    printf '  :\n' >> $DEB_BIN_DIR/DEBIAN/postrm
    printf 'fi\n' >> $DEB_BIN_DIR/DEBIAN/postrm
    chmod a+x $DEB_BIN_DIR/DEBIAN/postrm
}

thrift_copy_bin_files () {

    rm -rf $INST_BIN_DIR/../bin
    mkdir -p $INST_BIN_DIR/../bin

    pushd $INST_BIN_DIR
    find ./opt/quagga/lib -name *.so* | xargs tar cf - | tar xf - -C $INST_BIN_DIR/../bin
    tar cf - ./opt/quagga//bin | tar xf - -C $INST_BIN_DIR/../bin
    popd

    pushd $INST_BIN_DIR/../bin
    if [ $PACKAGE_DEB = "y" ]; then
       find . \! -type d | cpio -o -H ustar -R 0:0 | tar -C $DEB_BIN_DIR -x
    fi
    popd
}

thrift_rpm_bin_spec () {
    echo "Name: thrift" >> $RPM_SPEC_FILE
    if [ -z "$COMMITID" ]; then
        echo "Version: 1.0.0.$HOST_NAME" >> $RPM_SPEC_FILE
    else
        echo "Version: 1.0.0.$COMMITID.$HOST_NAME" >> $RPM_SPEC_FILE
    fi
    echo "Release: 0" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "Summary: thrift library" >> $RPM_SPEC_FILE
    echo "Group: Applications/Internet" >> $RPM_SPEC_FILE
    echo "License: Apache" >> $RPM_SPEC_FILE

    echo "BuildRoot: $RPM_BIN_DIR/BUILD/ROOT" >> $RPM_SPEC_FILE
    case $HOST_NAME in
    SUSE*)
        THRIFT_RPM_DEPS="libgobject-2_0-0"
        ;;
    esac
    if [ -n "$THRIFT_RPM_DEPS" ]; then
        echo "Requires: $THRIFT_RPM_DEPS" >> $RPM_SPEC_FILE
    fi
    echo >> $RPM_SPEC_FILE

    echo "%description" >> $RPM_SPEC_FILE
    printf "Library for THRIFT.\nTHRIFT_BUILD_DEPS=''\n" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%install" >> $RPM_SPEC_FILE
    echo "rm -rf %{buildroot} && mkdir -p %{buildroot}" >> $RPM_SPEC_FILE
    echo "cd $INST_BIN_DIR/../bin && find . \! -type d | cpio -o -H ustar -R 0:0 | tar -C %{buildroot} -x" >> $RPM_SPEC_FILE
    echo "find %{buildroot} -type f -o -type l|sed "s,%{buildroot},," > %{_builddir}/files" >> $RPM_SPEC_FILE
    echo "sed -ri "s/\.py$/\.py*/" %{_builddir}/files" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%clean" >> $RPM_SPEC_FILE
    echo "rm -rf %{buildroot}" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%pre" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%postun" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%post" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%preun" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%files -f %{_builddir}/files" >> $RPM_SPEC_FILE
    echo "%defattr(-,root,root)" >> $RPM_SPEC_FILE
}

thrift_deb_bin_control () {
    echo "Package: thrift" >> $DEB_CONTROL_FILE
    if [ -z "$COMMITID" ]; then
        echo "Version: 1.0.0.$HOST_NAME" >> $DEB_CONTROL_FILE
    else
        echo "Version: 1.0.0.$COMMITID.$HOST_NAME" >> $DEB_CONTROL_FILE
    fi
    echo "Architecture: amd64" >> $DEB_CONTROL_FILE
    echo "Maintainer: 6WIND <packaging@6wind.com>" >> $DEB_CONTROL_FILE
    echo "Depends: libglib2.0-0(>=2.22.5)" >> $DEB_CONTROL_FILE
    echo "Description: thrift library" >> $DEB_CONTROL_FILE
    printf " Library for THRIFT.\n  THRIFT_BUILD_DEPS=''\n" >> $DEB_CONTROL_FILE

    printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/postinst
    printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/postinst
    printf 'if [ "$1" = "configure" ]; then\n' >> $DEB_BIN_DIR/DEBIAN/postinst
    printf '  :\n' >> $DEB_BIN_DIR/DEBIAN/postinst
    printf 'fi\n' >> $DEB_BIN_DIR/DEBIAN/postinst
    chmod a+x $DEB_BIN_DIR/DEBIAN/postinst

    printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/prerm
    printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/prerm
    chmod a+x $DEB_BIN_DIR/DEBIAN/prerm

    printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/postrm
    printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/postrm
    printf 'if [ "$1" = "remove" ]; then\n' >> $DEB_BIN_DIR/DEBIAN/postrm
    printf '  :\n' >> $DEB_BIN_DIR/DEBIAN/postrm
    printf 'fi\n' >> $DEB_BIN_DIR/DEBIAN/postrm
    chmod a+x $DEB_BIN_DIR/DEBIAN/postrm
}

zmq_copy_bin_files () {

    rm -rf $INST_BIN_DIR/../bin
    mkdir -p $INST_BIN_DIR/../bin

    pushd $INST_BIN_DIR
    find ./opt/quagga/lib -name *.so* | xargs tar cf - | tar xf - -C $INST_BIN_DIR/../bin
    tar cf - ./opt/quagga/bin | tar xf - -C $INST_BIN_DIR/../bin
    popd

    pushd $INST_BIN_DIR/../bin
    if [ $PACKAGE_DEB = "y" ]; then
       find . \! -type d | cpio -o -H ustar -R 0:0 | tar -C $DEB_BIN_DIR -x
    fi
    popd
}

zmq_rpm_bin_spec () {
    echo "Name: zmq" >> $RPM_SPEC_FILE
    if [ -z "$COMMITID" ]; then
        echo "Version: 4.1.3.$HOST_NAME" >> $RPM_SPEC_FILE
    else
        echo "Version: 4.1.3.$COMMITID.$HOST_NAME" >> $RPM_SPEC_FILE
    fi
    echo "Release: 0" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "Summary: ZMQ library" >> $RPM_SPEC_FILE
    echo "Group: Applications/Internet" >> $RPM_SPEC_FILE
    echo "License: GPLv3" >> $RPM_SPEC_FILE

    echo "BuildRoot: $RPM_BIN_DIR/BUILD/ROOT" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%description" >> $RPM_SPEC_FILE
    printf "Zero Message Queue Library.\nZMQ_BUILD_DEPS=''\n" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%install" >> $RPM_SPEC_FILE
    echo "rm -rf %{buildroot} && mkdir -p %{buildroot}" >> $RPM_SPEC_FILE
    echo "cd $INST_BIN_DIR/../bin && find . \! -type d | cpio -o -H ustar -R 0:0 | tar -C %{buildroot} -x" >> $RPM_SPEC_FILE
    echo "find %{buildroot} -type f -o -type l|sed "s,%{buildroot},," > %{_builddir}/files" >> $RPM_SPEC_FILE
    echo "sed -ri "s/\.py$/\.py*/" %{_builddir}/files" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%clean" >> $RPM_SPEC_FILE
    echo "rm -rf %{buildroot}" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%pre" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%postun" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%post" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%preun" >> $RPM_SPEC_FILE
    echo >> $RPM_SPEC_FILE

    echo "%files -f %{_builddir}/files" >> $RPM_SPEC_FILE
    echo "%defattr(-,root,root)" >> $RPM_SPEC_FILE
}

zmq_deb_bin_control () {
    echo "Package: zmq" >> $DEB_CONTROL_FILE
    if [ -z "$COMMITID" ]; then
        echo "Version: 4.1.3.$HOST_NAME" >> $DEB_CONTROL_FILE
    else
        echo "Version: 4.1.3.$COMMITID.$HOST_NAME" >> $DEB_CONTROL_FILE
    fi
    echo "Architecture: amd64" >> $DEB_CONTROL_FILE
    echo "Maintainer: 6WIND <packaging@6wind.com>" >> $DEB_CONTROL_FILE
    echo "Description: ZMQ library" >> $DEB_CONTROL_FILE
    printf " Zero Message Queue Library.\n  ZMQ_BUILD_DEPS=''\n" >> $DEB_CONTROL_FILE

    printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/postinst
    printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/postinst
    printf 'if [ "$1" = "configure" ]; then\n' >> $DEB_BIN_DIR/DEBIAN/postinst
    printf '  :\n' >> $DEB_BIN_DIR/DEBIAN/postinst
    printf 'fi\n' >> $DEB_BIN_DIR/DEBIAN/postinst
    chmod a+x $DEB_BIN_DIR/DEBIAN/postinst

    printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/prerm
    printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/prerm
    chmod a+x $DEB_BIN_DIR/DEBIAN/prerm

    printf '#!/bin/sh\n' > $DEB_BIN_DIR/DEBIAN/postrm
    printf 'set -e\n' >> $DEB_BIN_DIR/DEBIAN/postrm
    printf 'if [ "$1" = "remove" ]; then\n' >> $DEB_BIN_DIR/DEBIAN/postrm
    printf '  :\n' >> $DEB_BIN_DIR/DEBIAN/postrm
    printf 'fi\n' >> $DEB_BIN_DIR/DEBIAN/postrm
    chmod a+x $DEB_BIN_DIR/DEBIAN/postrm
}

case $HOST_NAME in
Ubuntu*)
    PACKAGE_DEB="y"
    DEB_BIN_DIR=$3/deb/bin
    mkdir -p $DEB_BIN_DIR/DEBIAN
    DEB_CONTROL_FILE=$DEB_BIN_DIR/DEBIAN/control
    rm -f $DEB_CONTROL_FILE

    if [ $1 = "quagga" ]; then
        quagga_copy_bin_files
        quagga_deb_bin_control
    elif [ $1 = "thrift" ]; then
        thrift_copy_bin_files
        thrift_deb_bin_control
    elif [ $1 = "zmq" ]; then
        zmq_copy_bin_files
        zmq_deb_bin_control
    fi

    PKG_DIR=`dirname $0`
    fakeroot dpkg-deb -b $DEB_BIN_DIR $PKG_DIR
    ;;
RedHat*|CentOS*|SUSE*)
    RPM_BIN_DIR=$3/rpm/bin
    mkdir -p $RPM_BIN_DIR/BUILD
    mkdir -p $RPM_BIN_DIR/SPECS
    RPM_SPEC_FILE=$RPM_BIN_DIR/SPECS/rpm.spec
    rm -f $RPM_SPEC_FILE

    if [ $1 = "quagga" ]; then
        quagga_copy_bin_files
        quagga_rpm_bin_spec
    elif [ $1 = "thrift" ]; then
        thrift_copy_bin_files
        thrift_rpm_bin_spec
    elif [ $1 = "zmq" ]; then
        zmq_copy_bin_files
        zmq_rpm_bin_spec
    fi

    PKG_DIR=`dirname $0`
    rpmbuild -bb --define "_topdir $RPM_BIN_DIR" \
             --define "_rpmdir $PKG_DIR" \
             --define '_rpmfilename %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm' \
             --define 'debug_package %{nil}' $RPM_SPEC_FILE
    ;;
*)
    echo "unsupported distribution $HOST_NAME"
    exit 1
esac
