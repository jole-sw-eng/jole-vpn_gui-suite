# jole-vpn: OpenVPN 2.6 server image (+ optional LAN-only admin web UI, v2)
FROM debian:trixie-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      openvpn easy-rsa openssl iptables iproute2 ca-certificates procps python3 \
 && rm -rf /var/lib/apt/lists/*

COPY VERSION /usr/local/share/jole-vpn/VERSION
COPY bin/ /usr/local/bin/
COPY web/jolevpn_web/ /usr/local/lib/jole-vpn/jolevpn_web/
RUN chmod 0755 /usr/local/bin/jole-vpn-* /usr/local/bin/entrypoint.sh \
 && python3 -m compileall -q /usr/local/lib/jole-vpn

ENV JOLE_DIR=/etc/jole-vpn \
    JOLE_WEB=0 \
    WEB_LISTEN_PORT=8443
VOLUME ["/etc/jole-vpn"]
EXPOSE 1194/udp 8443/tcp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["serve"]
