# OpenPEC 2.2.8, the open-source PEC provider, as a reference provider for the provider tests.
# Crypt::SMimeEngine builds only against OpenSSL 1.0, so the base is Debian stretch from the archive.
FROM debian:stretch

# Postfix and slapd ask debconf questions on install, which a build cannot answer.
ENV DEBIAN_FRONTEND=noninteractive

RUN printf 'deb http://archive.debian.org/debian stretch main\ndeb http://archive.debian.org/debian-security stretch/updates main\n' > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends --allow-unauthenticated \
        build-essential ca-certificates curl openssl libssl1.0-dev perl \
        libnet-server-perl libsys-sigaction-perl libmailtools-perl libunix-syslog-perl \
        libio-stringy-perl libmime-tools-perl libnet-ldap-perl libwww-perl libnet-http-perl \
        postfix dovecot-imapd dovecot-lmtpd slapd ldap-utils \
    && rm -rf /var/lib/apt/lists/*

ARG SMIME_URL=https://cpan.metacpan.org/authors/id/F/FL/FLAZAN/Crypt-SMimeEngine-0.06.tar.gz
ARG SMIME_SHA256=c0a4fcc475adecf3a0d90fa94edfa234141482699ca111d655e5a7a8c92feeeb
RUN curl -fsSL -o /tmp/smime.tar.gz "$SMIME_URL" \
    && echo "$SMIME_SHA256  /tmp/smime.tar.gz" | sha256sum -c - \
    && tar xzf /tmp/smime.tar.gz -C /tmp \
    && cd /tmp/SMimeEngine-0.06 && perl Makefile.PL && make && make test && make install \
    && rm -rf /tmp/smime.tar.gz /tmp/SMimeEngine-0.06

ARG OPEC_URL=https://downloads.sourceforge.net/project/openpec/openpec/2.2.8/Opec-2.2.8.tar.gz
ARG OPEC_SHA256=7abba1366fb84dab1f715f6d3c5c5ac9fa083d38c940796520bea87dff28ee25
RUN curl -fsSL -o /tmp/opec.tar.gz "$OPEC_URL" \
    && echo "$OPEC_SHA256  /tmp/opec.tar.gz" | sha256sum -c - \
    && tar xzf /tmp/opec.tar.gz -C /tmp \
    && cd /tmp/Opec-2.2.8 && perl Makefile.PL && make && make install \
    && rm -rf /tmp/opec.tar.gz /tmp/Opec-2.2.8

# The tests send no virus, so OpenPEC's antivirus hook gets a module that finds none instead of a ClamAV daemon.
COPY None.pm /tmp/None.pm
RUN install -m 644 /tmp/None.pm "$(dirname "$(perl -MOpec::AV::Clamav -e 'print $INC{"Opec/AV/Clamav.pm"}')")/None.pm" \
    && rm /tmp/None.pm \
    && perl -MCrypt::SMimeEngine -MOpec::AV::None -MNet::Server -MMIME::Tools -MNet::LDAP -e 'print "modules ok\n"'

RUN useradd -r -m -d /home/dopec dopec && mv /etc/opec.conf /etc/opec.conf.dist
COPY pec.schema /etc/ldap/pec.schema
COPY opec-test.conf /etc/opec-test.conf
COPY start.sh /usr/local/bin/start-pec
EXPOSE 25 143
CMD ["/usr/local/bin/start-pec"]
