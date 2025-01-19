# Base image
FROM centos:7

# Replace default YUM repositories with CentOS Vault
RUN rm -rf /etc/yum.repos.d/* && \
    echo -e "[base]\n\
name=CentOS-7 - Base\n\
baseurl=http://vault.centos.org/7.9.2009/os/x86_64/\n\
enabled=1\n\
gpgcheck=1\n\
gpgkey=http://vault.centos.org/7.9.2009/os/x86_64/RPM-GPG-KEY-CentOS-7\n\n\
[updates]\n\
name=CentOS-7 - Updates\n\
baseurl=http://vault.centos.org/7.9.2009/updates/x86_64/\n\
enabled=1\n\
gpgcheck=1\n\
gpgkey=http://vault.centos.org/7.9.2009/os/x86_64/RPM-GPG-KEY-CentOS-7\n\n\
[extras]\n\
name=CentOS-7 - Extras\n\
baseurl=http://vault.centos.org/7.9.2009/extras/x86_64/\n\
enabled=1\n\
gpgcheck=1\n\
gpgkey=http://vault.centos.org/7.9.2009/os/x86_64/RPM-GPG-KEY-CentOS-7\n" > /etc/yum.repos.d/CentOS-Vault.repo && \
    yum clean all && \
    yum makecache fast

# Install development tools and required dependencies
RUN yum groupinstall -y "Development Tools" && \
    yum install -y wget gcc gcc-c++ make zlib-devel bzip2 bzip2-devel \
        xz-devel libffi-devel ncurses-devel sqlite sqlite-devel \
        openssl openssl-devel tk-devel gdbm-devel libuuid-devel \
        libnsl2-devel libtirpc-devel readline-devel uuid-devel tar && \
        binutils-aarch64-linux-gnu binutils-arm-linux-gnueabi && \
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
    ./configure --enable-optimizations \
                --enable-shared \
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

# Verify Python installation and SSL
RUN python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"

# Set working directory
WORKDIR /workspace

# Default command
CMD ["bash"]
