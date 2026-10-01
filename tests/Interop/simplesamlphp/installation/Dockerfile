# SimpleSAMLphp 2.5.3.1, its slim release archive pinned by the SHA-256 the release publishes, on PHP 8.4 and Apache.
# One image for both roles: compose.yaml mounts the configuration, the metadata and the keys of each.
FROM php:8.4.26-apache@sha256:75325cceea4f9a8200f4e9e146e8155ec1b6466b2957b87accf0286b94547cbd

ARG SIMPLESAMLPHP_VERSION=2.5.3.1
ARG SIMPLESAMLPHP_SHA256=38d81fc60f358b46a58df38617b02f97f57793dcbf8e491c1abcedb6706ffe3c

ADD https://github.com/simplesamlphp/simplesamlphp/releases/download/v${SIMPLESAMLPHP_VERSION}/simplesamlphp-${SIMPLESAMLPHP_VERSION}-slim.tar.gz /tmp/simplesamlphp.tar.gz

# The distributed config/ is kept as config-dist/: the mounted configuration reads it and overrides a few settings.
RUN echo "${SIMPLESAMLPHP_SHA256}  /tmp/simplesamlphp.tar.gz" | sha256sum -c - \
    && mkdir -p /var/simplesamlphp \
    && tar xzf /tmp/simplesamlphp.tar.gz -C /var/simplesamlphp --strip-components=1 \
    && rm /tmp/simplesamlphp.tar.gz \
    && cp -r /var/simplesamlphp/config /var/simplesamlphp/config-dist \
    && mkdir -p /var/cache/simplesamlphp \
    && chown www-data:www-data /var/cache/simplesamlphp \
    && printf '%s\n' 'Alias /simplesaml /var/simplesamlphp/public' '<Directory /var/simplesamlphp/public>' \
        '    Require all granted' '</Directory>' > /etc/apache2/conf-enabled/simplesamlphp.conf
