#!/bin/sh

# Convert HTTPS_CA_CERTIFICATES to REQUESTS_CA_BUNDLE if present
if [ -n "$HTTPS_CA_CERTIFICATES" ]; then
    echo "[ENTRYPOINT] Processing HTTPS_CA_CERTIFICATES environment variable"
    
    # Create directory for certificates
    mkdir -p /tmp/certs
    
    # Write the certificate to a file
    echo "$HTTPS_CA_CERTIFICATES" > /tmp/certs/proxy-ca-bundle.crt
    
    # Check if system certificates exist and combine them
    if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
        echo "[ENTRYPOINT] Combining proxy certificate with system certificates"
        cat /etc/ssl/certs/ca-certificates.crt >> /tmp/certs/proxy-ca-bundle.crt
    elif [ -f /etc/pki/tls/certs/ca-bundle.crt ]; then
        echo "[ENTRYPOINT] Combining proxy certificate with system certificates"
        cat /etc/pki/tls/certs/ca-bundle.crt >> /tmp/certs/proxy-ca-bundle.crt
    fi
    
    # Export REQUESTS_CA_BUNDLE for the requests library
    export REQUESTS_CA_BUNDLE=/tmp/certs/proxy-ca-bundle.crt
    export SSL_CERT_FILE=/tmp/certs/proxy-ca-bundle.crt
    export CURL_CA_BUNDLE=/tmp/certs/proxy-ca-bundle.crt
    
    echo "[ENTRYPOINT] Certificate bundle configured at: $REQUESTS_CA_BUNDLE"
fi

# Execute the connector
exec python -m src "$@"