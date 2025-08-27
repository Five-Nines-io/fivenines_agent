FROM quay.io/pypa/manylinux_2_34_x86_64

RUN yum install -y libvirt-devel && \
    yum clean all

# Use manylinux2014 for better compatibility with CentOS 7 systems
FROM quay.io/pypa/manylinux2014_x86_64

RUN yum install -y wget curl tar bzip2 xz which \
        openssl11 openssl11-devel zlib-devel bzip2-devel xz-devel libffi-devel \
        ncurses-devel sqlite-devel tk-devel gdbm-devel libuuid-devel \
        readline-devel && \
    yum clean all


# Build OpenSSL from source
RUN curl -LO https://www.openssl.org/source/openssl-1.1.1u.tar.gz && \
    tar -xzf openssl-1.1.1u.tar.gz && \
    cd openssl-1.1.1u && \
    ./config --prefix=/usr/local/openssl --openssldir=/usr/local/openssl && \
    make -j$(nproc) && \
    make install && \
    cd .. && rm -rf openssl-1.1.1u openssl-1.1.1u.tar.gz && \
    echo "/usr/local/openssl/lib" > /etc/ld.so.conf.d/openssl.conf && ldconfig

# Build Python from source
RUN curl -O https://www.python.org/ftp/python/3.10.12/Python-3.10.12.tgz && \
    tar -xzf Python-3.10.12.tgz && \
    cd Python-3.10.12 && \
    ./configure --enable-shared \
                --with-ssl-default-suites=openssl \
                --with-openssl=/usr/local/openssl \
                LDFLAGS="-L/usr/local/openssl/lib -L/usr/lib64 -Wl,-rpath,/usr/local/openssl/lib" \
                CPPFLAGS="-I/usr/local/openssl/include -I/usr/include" \
                LIBS="-lpthread -ldl" && \
    make clean && \
    LD_LIBRARY_PATH=/usr/local/openssl/lib make -j$(nproc) && \
    make altinstall && \
    ln -s /usr/local/bin/python3.10 /usr/bin/python3 && \
    ln -s /usr/local/bin/pip3.10 /usr/bin/pip3 && \
    cd .. && rm -rf Python-3.10.12 Python-3.10.12.tgz && \
    echo "/usr/local/lib" > /etc/ld.so.conf.d/python3.conf && ldconfig

# Add Python shared library path
ENV LD_LIBRARY_PATH="/usr/local/lib:/usr/local/openssl/lib:$LD_LIBRARY_PATH"

# Copy libvirt libraries from the manylinux_2_34_x86_64 stage
COPY --from=0 /usr/lib64/libvirt.so* /usr/lib64/
COPY --from=0 /usr/lib64/libvirt-qemu.so* /usr/lib64/
COPY --from=0 /usr/lib64/libvirt-lxc.so* /usr/lib64/

COPY --from=0 /usr/include/libvirt/libvirt-common.h /usr/include/libvirt/libvirt-common.h
COPY --from=0 /usr/include/libvirt/libvirt.h /usr/include/libvirt/libvirt.h
COPY --from=0 /usr/include/libvirt/libvirt-secret.h /usr/include/libvirt/libvirt-secret.h
COPY --from=0 /usr/include/libvirt/libvirt-domain-snapshot.h /usr/include/libvirt/libvirt-domain-snapshot.h
COPY --from=0 /usr/include/libvirt/libvirt-domain.h /usr/include/libvirt/libvirt-domain.h
COPY --from=0 /usr/include/libvirt/libvirt-event.h /usr/include/libvirt/libvirt-event.h
COPY --from=0 /usr/include/libvirt/libvirt-nodedev.h /usr/include/libvirt/libvirt-nodedev.h

COPY --from=0 /usr/include/libvirt/libvirt-lxc.h /usr/include/libvirt/libvirt-lxc.h
COPY --from=0 /usr/include/libvirt/libvirt-host.h /usr/include/libvirt/libvirt-host.h
COPY --from=0 /usr/include/libvirt/libvirt-domain-checkpoint.h /usr/include/libvirt/libvirt-domain-checkpoint.h
COPY --from=0 /usr/include/libvirt/libvirt-storage.h /usr/include/libvirt/libvirt-storage.h
COPY --from=0 /usr/include/libvirt/libvirt-stream.h /usr/include/libvirt/libvirt-stream.h
COPY --from=0 /usr/include/libvirt/libvirt-nwfilter.h /usr/include/libvirt/libvirt-nwfilter.h
COPY --from=0 /usr/include/libvirt/libvirt-interface.h /usr/include/libvirt/libvirt-interface.h
COPY --from=0 /usr/include/libvirt/libvirt-qemu.h /usr/include/libvirt/libvirt-qemu.h
COPY --from=0 /usr/include/libvirt/libvirt-network.h /usr/include/libvirt/libvirt-network.h
COPY --from=0 /usr/include/libvirt/libvirt-admin.h /usr/include/libvirt/libvirt-admin.h


COPY --from=0 /usr/lib64/libvirt.so* /usr/lib64/
COPY --from=0 /usr/lib64/libvirt-qemu.so* /usr/lib64/
COPY --from=0 /usr/lib64/libvirt-lxc.so* /usr/lib64/

# Verify Python installation
RUN python3 --version

ENV TARGET_ARCH="amd64"
# Set working directory
WORKDIR /workspace

# Default command
CMD ["bash"]
