#!/bin/sh
set -eu

TLS_DIR="/data/tls"
echo "[nginx-entry] waiting for TLS certificate in ${TLS_DIR}..."
while [ ! -s "${TLS_DIR}/fullchain.pem" ] || [ ! -s "${TLS_DIR}/privkey.pem" ]; do
    sleep 1
done

calc_hash() {
    sha256sum "${TLS_DIR}/fullchain.pem" "${TLS_DIR}/privkey.pem" 2>/dev/null | sha256sum | awk '{print $1}'
}

LAST_HASH="$(calc_hash)"

# Background watcher: reload nginx whenever exported TLS cert changes
(
    while sleep 15; do
        if [ -s "${TLS_DIR}/fullchain.pem" ] && [ -s "${TLS_DIR}/privkey.pem" ]; then
            CUR_HASH="$(calc_hash)"
            if [ "${CUR_HASH}" != "${LAST_HASH}" ]; then
                if nginx -t >/dev/null 2>&1; then
                    echo "[nginx-entry] TLS certificate updated, reloading nginx..."
                    nginx -s reload
                    LAST_HASH="${CUR_HASH}"
                else
                    echo "[nginx-entry] warning: nginx -t failed, skipping reload"
                fi
            fi
        fi
    done
) &

exec nginx -g "daemon off;"
