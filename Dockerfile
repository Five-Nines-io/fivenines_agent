FROM quay.io/pypa/manylinux_2_28_x86_64

# Install system packages
RUN yum install -y \
    libvirt-devel \
    gcc \
    gcc-c++ \
    make \
    pkgconfig \
    && yum clean all

# Find Python 3.11 installation and set it up
RUN echo "=== Finding Python 3.11 ===" && \
    PYTHON_311_PATH="" && \
    for pydir in /opt/python/cp311*; do \
        if [ -d "$pydir" ] && [ -f "$pydir/bin/python" ]; then \
            version=$($pydir/bin/python --version 2>&1 | grep "3.11" || true); \
            if [ -n "$version" ]; then \
                PYTHON_311_PATH="$pydir"; \
                echo "Found Python 3.11 at: $pydir"; \
                echo "Version: $version"; \
                break; \
            fi; \
        fi; \
    done && \
    if [ -z "$PYTHON_311_PATH" ]; then \
        echo "Python 3.11 not found in /opt/python/"; \
        exit 1; \
    fi && \
    echo "PYTHON_311_PATH=$PYTHON_311_PATH" > /etc/python_path

# Set up environment and symlinks
RUN PYTHON_311_PATH=$(cat /etc/python_path | cut -d= -f2) && \
    echo "Setting up Python 3.11 from: $PYTHON_311_PATH" && \
    echo "export PATH=\"$PYTHON_311_PATH/bin:\$PATH\"" >> /etc/profile && \
    echo "export PYTHON_ROOT=\"$PYTHON_311_PATH\"" >> /etc/profile && \
    ln -sf $PYTHON_311_PATH/bin/python /usr/local/bin/python3 && \
    ln -sf $PYTHON_311_PATH/bin/python /usr/local/bin/python && \
    ln -sf $PYTHON_311_PATH/bin/pip /usr/local/bin/pip3 && \
    ln -sf $PYTHON_311_PATH/bin/pip /usr/local/bin/pip

# Source the profile to set PATH
ENV BASH_ENV=/etc/profile
RUN . /etc/profile && \
    python --version && \
    python -m pip install --upgrade pip

# Verify Python.h is available
RUN . /etc/profile && \
    echo "=== Python installation details ===" && \
    python -c "import sys; print('Python executable:', sys.executable)" && \
    python -c "import sysconfig; print('Include path:', sysconfig.get_path('include'))" && \
    PYTHON_311_PATH=$(cat /etc/python_path | cut -d= -f2) && \
    find $PYTHON_311_PATH -name "Python.h" && \
    echo "Python 3.11 setup complete!"

ENV TARGET_ARCH="amd64"
WORKDIR /workspace
CMD ["bash"]
