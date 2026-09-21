#!/usr/bin/env bash
#
# build.sh
#
# libmodsecurity(v3)와 ModSecurity-nginx 커넥터를 포함한 nginx를 소스에서
# 빌드하여 ./install/ 아래에 설치한다.
#
#   src/ModSecurity          -> install/modsecurity
#   src/nginx (+ connector)  -> install/nginx
#
# 사용법:
#   ./build.sh                 # 의존성 설치 + 전체 빌드
#   ./build.sh --no-deps       # apt 설치 건너뜀
#   ./build.sh --only-modsec   # libmodsecurity만 빌드
#   ./build.sh --only-nginx    # nginx만 빌드 (libmodsecurity 설치 선행 필요)
#   ./build.sh --clean         # 기존 빌드 산출물/설치본 제거 후 빌드
#   ./build.sh -j 4            # 병렬 빌드 job 수 지정
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$ROOT_DIR/src"
INSTALL_DIR="$ROOT_DIR/install"

MODSEC_SRC="$SRC_DIR/ModSecurity"
NGINX_SRC="$SRC_DIR/nginx"
CONNECTOR_SRC="$SRC_DIR/ModSecurity-nginx"
CONNECTOR_REPO="https://github.com/owasp-modsecurity/ModSecurity-nginx.git"

MODSEC_PREFIX="$INSTALL_DIR/modsecurity"
NGINX_PREFIX="$INSTALL_DIR/nginx"

JOBS="$(nproc 2>/dev/null || echo 2)"
DO_DEPS=1
DO_MODSEC=1
DO_NGINX=1
DO_CLEAN=0

DEPS=(
    build-essential autoconf automake libtool libtool-bin pkg-config m4
    libpcre2-dev zlib1g-dev libssl-dev libxml2-dev libyajl-dev
    libcurl4-openssl-dev liblua5.4-dev liblmdb-dev
)

log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[!] %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31m[x] %s\033[0m\n' "$*" >&2; exit 1; }

usage() {
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --no-deps)     DO_DEPS=0 ;;
        --only-modsec) DO_NGINX=0 ;;
        --only-nginx)  DO_MODSEC=0 ;;
        --clean)       DO_CLEAN=1 ;;
        -j)            JOBS="$2"; shift ;;
        -j*)           JOBS="${1#-j}" ;;
        -h|--help)     usage; exit 0 ;;
        *) die "알 수 없는 옵션: $1 (--help 참고)" ;;
    esac
    shift
done

as_root() {
    if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}

install_deps() {
    log "빌드 의존성 설치 (apt)"
    as_root apt-get update -qq
    DEBIAN_FRONTEND=noninteractive as_root apt-get install -y -qq "${DEPS[@]}"
}

ensure_connector() {
    if [ ! -f "$CONNECTOR_SRC/config" ]; then
        log "ModSecurity-nginx 커넥터가 없어 clone 합니다"
        git clone --depth 1 "$CONNECTOR_REPO" "$CONNECTOR_SRC"
    fi
}

init_submodules() {
    log "ModSecurity git submodule 초기화 (libinjection, mbedtls)"
    cd "$MODSEC_SRC"
    for sub in others/libinjection others/mbedtls; do
        if [ -z "$(ls -A "$sub" 2>/dev/null)" ]; then
            git submodule update --init --recursive "$sub"
        fi
    done
}

clean_all() {
    log "기존 빌드 산출물 정리"
    ( cd "$MODSEC_SRC" && { [ -f Makefile ] && make distclean >/dev/null 2>&1 || true; } )
    ( cd "$NGINX_SRC"  && { [ -f Makefile ] && make clean    >/dev/null 2>&1 || true; } )
    rm -rf "$MODSEC_PREFIX" "$NGINX_PREFIX"
}

build_modsecurity() {
    log "libmodsecurity 빌드 (prefix=$MODSEC_PREFIX)"
    cd "$MODSEC_SRC"
    ./build.sh
    ./configure \
        --prefix="$MODSEC_PREFIX" \
        --with-pcre2 \
        --with-yajl \
        --with-libxml \
        --with-lua \
        --with-curl \
        --with-lmdb \
        --disable-examples
    make -j"$JOBS"
    make install
}

build_nginx() {
    log "nginx + ModSecurity-nginx 커넥터 빌드 (prefix=$NGINX_PREFIX)"
    [ -f "$MODSEC_PREFIX/include/modsecurity/modsecurity.h" ] \
        || die "libmodsecurity가 $MODSEC_PREFIX 에 설치되어 있지 않습니다. 먼저 --only-modsec 빌드를 수행하세요."
    cd "$NGINX_SRC"
    CONFIG_OPTS=(
        --prefix="$NGINX_PREFIX"
        --with-pcre
        --with-http_ssl_module
        --with-http_v2_module
        --with-http_realip_module
        --with-http_stub_status_module
        --with-http_gzip_static_module
        --with-cc-opt="-I$MODSEC_PREFIX/include"
        --with-ld-opt="-L$MODSEC_PREFIX/lib -Wl,-rpath,$MODSEC_PREFIX/lib"
        --add-module="$CONNECTOR_SRC"
    )
    MODSECURITY_INC="$MODSEC_PREFIX/include" \
    MODSECURITY_LIB="$MODSEC_PREFIX/lib" \
        ./auto/configure "${CONFIG_OPTS[@]}"
    make -j"$JOBS"
    make install
}

verify() {
    log "빌드 결과 검증"
    echo "- libmodsecurity:"
    ls -1 "$MODSEC_PREFIX/lib"/libmodsecurity.so* 2>/dev/null || warn "libmodsecurity.so 없음"
    echo "- modsecurity header:"
    ls -1 "$MODSEC_PREFIX/include/modsecurity/modsecurity.h" 2>/dev/null || warn "header 없음"
    echo "- nginx binary:"
    "$NGINX_PREFIX/sbin/nginx" -V 2>&1 | sed 's/^/    /'
    echo "- nginx -> libmodsecurity link:"
    ldd "$NGINX_PREFIX/sbin/nginx" | grep -i modsecurity || warn "libmodsecurity 미링크"
}

main() {
    [ -d "$SRC_DIR" ] || die "소스 디렉토리가 없습니다: $SRC_DIR"
    mkdir -p "$INSTALL_DIR"

    [ "$DO_DEPS" -eq 1 ] && install_deps

    if [ "$DO_CLEAN" -eq 1 ]; then
        clean_all
    fi

    if [ "$DO_NGINX" -eq 1 ]; then
        ensure_connector
    fi

    if [ "$DO_MODSEC" -eq 1 ]; then
        init_submodules
        build_modsecurity
    fi

    [ "$DO_NGINX" -eq 1 ] && build_nginx

    verify
    log "완료: modsecurity=$MODSEC_PREFIX  nginx=$NGINX_PREFIX"
}

main
