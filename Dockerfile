FROM centos:7

# Update repository configuration to use the CentOS Vault
RUN mv /etc/yum.repos.d /etc/yum.repos.d.bak && \
    mkdir /etc/yum.repos.d && \
    echo -e "[base]\nname=CentOS-7 - Base\nbaseurl=http://vault.centos.org/7.9.2009/os/\$basearch/\ngpgcheck=1\ngpgkey=http://vault.centos.org/7.9.2009/os/\$basearch/RPM-GPG-KEY-CentOS-7\n\n[updates]\nname=CentOS-7 - Updates\nbaseurl=http://vault.centos.org/7.9.2009/updates/\$basearch/\ngpgcheck=1\ngpgkey=http://vault.centos.org/7.9.2009/os/\$basearch/RPM-GPG-KEY-CentOS-7\n\n[extras]\nname=CentOS-7 - Extras\nbaseurl=http://vault.centos.org/7.9.2009/extras/\$basearch/\ngpgcheck=1\ngpgkey=http://vault.centos.org/7.9.2009/os/\$basearch/RPM-GPG-KEY-CentOS-7" > /etc/yum.repos.d/CentOS-Vault.repo && \
    yum clean all && \
    yum makecache fast && \
    yum update -y

# Install required development tools and dependencies
RUN yum groupinstall -y "Development Tools" && \
    yum install -y wget gcc gcc-c++ make zlib-devel bzip2 bzip2-devel \
        xz-devel libffi-devel ncurses-devel sqlite sqlite-devel \
        openssl-devel tk-devel && \
    yum clean all

# Install Python (customizable version)
RUN curl -O https://www.python.org/ftp/python/3.10.12/Python-3.10.12.tgz && \
    tar -xzf Python-3.10.12.tgz && \
    cd Python-3.10.12 && \
    ./configure --enable-optimizations && \
    make -j$(nproc) && \
    make altinstall && \
    ln -s /usr/local/bin/python3.10 /usr/bin/python3 && \
    ln -s /usr/local/bin/pip3.10 /usr/bin/pip3

# Install py2exe and other dependencies
RUN pip3 install --upgrade pip && \
    pip3 install py2exe setuptools wheel

# Set the working directory
WORKDIR /workspace

# Copy project files into the container
COPY . /workspace

# Default command
CMD ["bash"]
