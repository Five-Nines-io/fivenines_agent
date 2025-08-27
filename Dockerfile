FROM quay.io/pypa/manylinux_2_28_x86_64

RUN yum install -y wget curl tar bzip2 xz which \
        openssl11 openssl11-devel zlib-devel bzip2-devel xz-devel libffi-devel \
        ncurses-devel sqlite-devel tk-devel gdbm-devel libuuid-devel \
        readline-devel libvirt-devel && \
    yum clean all

# Verify Python installation
RUN python3 --version

ENV TARGET_ARCH="amd64"
# Set working directory
WORKDIR /workspace

# Default command
CMD ["bash"]
