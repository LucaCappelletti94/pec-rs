#!/usr/bin/env bash
# Starts one OpenPEC test provider for the domain pec.test: slapd with its provider index entry, Dovecot for LMTP
# delivery and IMAP, Postfix routing every message through OpenPEC, and OpenPEC itself.
set -euo pipefail

domain=pec.test
home=/home/dopec/MYHOME
certs=$home/certs

# A throwaway CA and the provider certificate it signs, made fresh on every start.
mkdir -p "$certs"
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/C=IT/O=PEC Test CA/CN=PEC Test CA" \
  -keyout "$certs/ca.key" -out "$certs/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes \
  -subj "/C=IT/O=Gestore PEC di Prova/CN=posta-certificata@$domain/emailAddress=posta-certificata@$domain" \
  -keyout "$certs/key.pem" -out "$certs/provider.csr" 2>/dev/null
openssl x509 -req -in "$certs/provider.csr" -CA "$certs/ca.pem" -CAkey "$certs/ca.key" -CAcreateserial -days 3650 \
  -extfile <(printf 'keyUsage=critical,digitalSignature,nonRepudiation\nextendedKeyUsage=emailProtection\nsubjectAltName=email:posta-certificata@%s\n' "$domain") \
  -out "$certs/cert.pem" 2>/dev/null
c_rehash "$certs" >/dev/null 2>&1
chown -R dopec:dopec "$home"

# The provider index of RFC 6109 §4.5, holding this provider alone.
hash=$(openssl x509 -in "$certs/cert.pem" -outform DER | sha1sum | cut -d' ' -f1 | tr a-f A-F)
der=$(openssl x509 -in "$certs/cert.pem" -outform DER | base64 -w0)
mkdir -p /var/lib/ldap-pec
cat >/etc/ldap/slapd-pec.conf <<EOF
include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/pec.schema
pidfile /run/slapd-pec.pid
modulepath /usr/lib/ldap
moduleload back_mdb
database mdb
suffix "o=postacert"
rootdn "cn=admin,o=postacert"
rootpw admin
directory /var/lib/ldap-pec
access to * by * read
EOF
slapadd -f /etc/ldap/slapd-pec.conf <<EOF
dn: o=postacert
objectClass: top
objectClass: organization
o: postacert

dn: providerName=Gestore PEC di Prova,o=postacert
objectClass: top
objectClass: provider
providerName: Gestore PEC di Prova
providerCertificateHash: $hash
providerCertificate;binary:: $der
mailReceipt: posta-certificata@$domain
managedDomains: $domain
EOF
slapd -f /etc/ldap/slapd-pec.conf -h ldap://127.0.0.1/

# Mailboxes: posta-certificata for the provider and the two the tests send between, all with the password prova.
cat >/etc/dovecot/local.conf <<EOF
protocols = imap lmtp
disable_plaintext_auth = no
auth_mechanisms = plain login
passdb {
  driver = passwd-file
  args = scheme=PLAIN /etc/dovecot/users
}
userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/mail/vmail/%d/%n
}
service lmtp {
  inet_listener lmtp {
    address = 127.0.0.1
    port = 24
  }
}
mail_location = maildir:/var/mail/vmail/%d/%n
EOF
: >/etc/dovecot/users
for user in posta-certificata mittente destinatario; do
  printf '%s@%s:{PLAIN}prova\n' "$user" "$domain" >>/etc/dovecot/users
done
id vmail >/dev/null 2>&1 || useradd -r -d /var/mail/vmail vmail
mkdir -p /var/mail/vmail && chown -R vmail:vmail /var/mail/vmail
dovecot

# Postfix: whatever arrives on 25 passes through OpenPEC on 10024. OpenPEC returns its messages on 10025, and those
# for the local domain go back through 25, so the same OpenPEC also acts as the receiving provider.
postconf -e "myhostname = mail.$domain" "mydestination = localhost" "inet_interfaces = all" \
  "mynetworks = 0.0.0.0/0" "relay_domains = $domain" "content_filter = smtp:[127.0.0.1]:10024" \
  "transport_maps = hash:/etc/postfix/transport" "smtputf8_enable = no"
printf '%s smtp:[127.0.0.1]:25\n' "$domain" >/etc/postfix/transport
postmap /etc/postfix/transport
cat >>/etc/postfix/master.cf <<EOF
127.0.0.1:10025 inet n - n - - smtpd
  -o content_filter=
  -o receive_override_options=no_header_body_checks,no_unknown_recipient_checks
  -o mynetworks=127.0.0.0/8
EOF
postfix start

cat /etc/opec.conf.dist /etc/opec-test.conf >/etc/opec.conf
exec opec -c /etc/opec.conf debug
