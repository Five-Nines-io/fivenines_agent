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

# Install required development tools and dependencies
RUN yum groupinstall -y "Development Tools" && \
    yum install -y wget gcc gcc-c++ make zlib-devel bzip2 bzip2-devel \
        xz-devel libffi-devel ncurses-devel sqlite sqlite-devel \
        openssl openssl-devel tk-devel gdbm-devel libuuid-devel \
        libnsl2-devel libtirpc-devel xz xz-libs && \
    yum clean all

# Install Python (customizable version)
RUN curl -O https://www.python.org/ftp/python/3.10.12/Python-3.10.12.tgz && \
    tar -xzf Python-3.10.12.tgz && \
    cd Python-3.10.12 && \
    ./configure --enable-optimizations --with-ssl --with-system-ffi --enable-shared && \
    make -j$(nproc) LD_LIBRARY_PATH=/usr/local/lib && \
    make altinstall && \
    ln -s /usr/local/bin/python3.10 /usr/bin/python3 && \
    ln -s /usr/local/bin/pip3.10 /usr/bin/pip3 && \
    cd .. && rm -rf Python-3.10.12 Python-3.10.12.tgz && \
    echo "/usr/local/lib" > /etc/ld.so.conf.d/python3.conf && ldconfig

# Set the working directory
WORKDIR /workspace

COPY . /workspace

# Default command
CMD ["bash"]
