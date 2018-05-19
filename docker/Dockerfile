FROM mritd/shadowsocks

EXPOSE 443/tcp 443/udp 444/udp
ENTRYPOINT ["/usr/bin/entry"]

RUN set -x \
  && apk add --update supervisor \
  && rm -rf /var/cache/apk/* /entrypoint.sh \
  && echo "#!/bin/sh" > /usr/bin/show \
  && echo "/usr/bin/entry 127.0.0.1 show" > /usr/bin/show \
  && chmod +x /usr/bin/show

COPY ./entrypoint.py /usr/bin/entry
COPY ./supervisord.obfs.conf ./supervisord.kcptun.conf /etc/supervisor/
