FROM debian:bookworm-slim

ARG JADX_VERSION=1.5.2

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH=/opt/re-tools/venv/bin:/opt/re-tools/bin:/opt/jadx/bin:$PATH

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      bash \
      coreutils \
      curl \
      wget \
      unzip \
      zip \
      xz-utils \
      git \
      make \
      python3 \
      python3-venv \
      python3-pip \
      openjdk-17-jre-headless \
      apktool \
      aapt \
      apksigner \
      zipalign \
      file \
      binutils \
      binutils-aarch64-linux-gnu \
      binutils-arm-linux-gnueabihf \
      binutils-i686-linux-gnu \
      binutils-x86-64-linux-gnu \
      gdb-multiarch \
      strace \
      ltrace \
      llvm \
      ripgrep \
      jq \
      less \
      nano \
      vim-tiny \
      tree \
      yara \
    && mkdir -p /opt/jadx \
    && curl -fsSL "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -o /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && rm /tmp/jadx.zip \
    && python3 -m venv /opt/re-tools/venv \
    && /opt/re-tools/venv/bin/pip install --no-cache-dir --upgrade pip wheel \
    && /opt/re-tools/venv/bin/pip install --no-cache-dir androguard lief capstone keystone-engine pycryptodome requests \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY bin/ /opt/re-tools/bin/
RUN chmod +x /opt/re-tools/bin/*

WORKDIR /work
CMD ["bash"]
