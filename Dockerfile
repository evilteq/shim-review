FROM ubuntu:noble

ARG SHIM_URL="https://github.com/rhboot/shim/releases/download/15.8/shim-15.8.tar.bz2"
ARG SHIM_HASH="a79f0a9b89f3681ab384865b1a46ab3f79d88b11b4ca59aa040ab03fffae80a9  shim-15.8.tar.bz2"

# dependencies
RUN apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq --no-install-recommends install build-essential ca-certificates curl

WORKDIR /build


# download shim, verify, extract
RUN curl --silent --location --remote-name ${SHIM_URL} && \
    echo "${SHIM_HASH}" | sha256sum --check && \
    tar -jxvpf $(basename ${SHIM_URL}) && \
    rm $(basename ${SHIM_URL})

WORKDIR /build/shim-15.8
ADD *.patch .
# Our certificate
ADD blancco_sb_2022.cer .
# include custom sbat
ADD blancco_sbat.csv .
# build
RUN for p in *.patch; do patch -p1 < $p; done && \
    cat blancco_sbat.csv >> data/sbat.csv && \
    mkdir build-x64 build-ia32 && \
    make -C build-x64 ARCH=x86_64 ENABLE_HTTPBOOT=true VENDOR_CERT_FILE=../blancco_sb_2022.cer DEFAULT_LOADER=\\\\grub.efi TOPDIR=.. -f ../Makefile && \
    make -C build-ia32 ARCH=ia32 ENABLE_HTTPBOOT=true VENDOR_CERT_FILE=../blancco_sb_2022.cer DEFAULT_LOADER=\\\\grub.efi TOPDIR=.. -f ../Makefile

# output
RUN mkdir /build/output && \
    cp build-x64/shimx64.efi build-x64/shimx64.nx.efi /build/output && \
    cp build-ia32/shimia32.efi build-ia32/shimia32.nx.efi /build/output && \
    objdump -j .sbat -s /build/output/*.efi && \
    sha256sum /build/output/*.efi
