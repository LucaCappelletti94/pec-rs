#!/usr/bin/env bash
# Recreates the throwaway test PKI and every signed message under messages/.
# Run from anywhere. Needs openssl 3.4.
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p pki messages
# Fixed validity, so the instants the tests check hold whenever the PKI is recreated.
not_before=20261101000000Z not_after=21261001000000Z
# The chain mirrors the AgID one: a root, a subordinate CA standing for AgID CA1, and a provider certificate with the
# profile of the AgID CPS (§7.1.2.3), signed with RSA and SHA-256 as the CPS requires (§7.1.3).
if [[ ! -f pki/provider.pem ]]; then
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 36500 \
    -subj "/C=IT/O=PEC Test Root CA/CN=PEC Test Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout pki/root.key -out pki/root.pem 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/C=IT/L=Roma/O=PEC Test CA/CN=PEC Test CA1" \
    -keyout pki/ca.key -out pki/ca.csr 2>/dev/null
  openssl x509 -req -sha256 -in pki/ca.csr -CA pki/root.pem -CAkey pki/root.key -CAcreateserial \
    -not_before "$not_before" -not_after "$not_after" \
    -extfile <(printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nextendedKeyUsage=emailProtection\n') \
    -out pki/ca.pem 2>/dev/null
  openssl req -newkey rsa:2048 -nodes \
    -subj "/C=IT/ST=Roma/L=Roma/O=Gestore PEC di Esempio S.p.A./CN=Gestore PEC di Esempio S.p.A." \
    -keyout pki/provider.key -out pki/provider.csr 2>/dev/null
  openssl x509 -req -sha256 -in pki/provider.csr -CA pki/ca.pem -CAkey pki/ca.key -CAcreateserial \
    -not_before "$not_before" -not_after "$not_after" \
    -extfile <(printf 'keyUsage=critical,digitalSignature\nextendedKeyUsage=emailProtection\nsubjectAltName=email:posta-certificata@pec.example.it\n') \
    -out pki/provider.pem 2>/dev/null
  openssl x509 -in pki/provider.pem -outform DER -out pki/provider.der
  openssl pkcs8 -topk8 -nocrypt -in pki/provider.key -outform DER -out pki/provider.key.der
  rm -f pki/ca.csr pki/provider.csr pki/root.srl pki/ca.srl
fi

# The test CA re-issued with each form of name constraint, agid-like.der in AgID's own form (CPS §7.1.5), and the
# provider key certified with each defect of the profile. Both reuse the keys above, so every fixture still verifies.
if [[ ! -f pki/anchors/agid-like.der ]]; then
  mkdir -p pki/anchors pki/signers
  csr=$(mktemp)
  serial=100
  names=$'[provider]\nC=IT\nST=Roma\nL=Roma\nO=Gestore PEC di Esempio S.p.A.\n[other]\nC=IT\nO=Altro Gestore PEC S.p.A.'
  # anchor NAME NAME_CONSTRAINTS
  anchor() {
    serial=$((serial + 1))
    openssl x509 -req -sha256 -in "$csr" -CA pki/root.pem -CAkey pki/root.key -set_serial "$serial" \
      -not_before "$not_before" -not_after "$not_after" \
      -extensions ext -extfile <(printf '[ext]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nextendedKeyUsage=emailProtection\nnameConstraints=critical,%s\n%s\n' "$2" "$names") \
      -outform DER -out "pki/anchors/$1.der" 2>/dev/null
  }
  openssl req -new -key pki/ca.key -subj "/C=IT/L=Roma/O=PEC Test CA/CN=PEC Test CA1" -out "$csr"
  anchor agid-like 'permitted;email:pec.example.com,permitted;email:pec.example.it,permitted;dirName:other,permitted;dirName:provider,excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0,excluded;DNS:example.it'
  anchor mailbox 'permitted;email:posta-certificata@PEC.EXAMPLE.IT'
  anchor other-mailbox 'permitted;email:protocollo@pec.example.it'
  anchor subdomains 'permitted;email:.example.it'
  anchor subdomains-only 'permitted;email:.pec.example.it'
  anchor other-host 'permitted;email:pec.example.com'
  anchor excluded-host 'excluded;email:PEC.example.it'
  anchor other-organisation 'permitted;dirName:other'
  anchor excluded-organisation 'excluded;dirName:other'
  # A SEQUENCE holding an INTEGER, which no NameConstraints is.
  anchor unreadable-constraints 'DER:3003020100'
  # The permitted email subtree of pec.example.it with a minimum, then a maximum, of 1, which RFC 5280 §4.2.1.10
  # forbids for every name form.
  anchor minimum 'DER:3017a0153013810e7065632e6578616d706c652e6974800101'
  anchor maximum 'DER:3017a0153013810e7065632e6578616d706c652e6974810101'
  openssl x509 -in pki/ca.pem -outform DER -out pki/anchors/unconstrained.der
  # signer NAME DIGEST EXTENSIONS
  signer() {
    serial=$((serial + 1))
    openssl x509 -req "-$2" -in "$csr" -CA pki/ca.pem -CAkey pki/ca.key -set_serial "$serial" \
      -not_before "$not_before" -not_after "$not_after" \
      -extfile <(printf '%s\n' "$3") -outform DER -out "pki/signers/$1.der" 2>/dev/null
  }
  openssl req -new -key pki/provider.key \
    -subj "/C=IT/ST=Roma/L=Roma/O=Gestore PEC di Esempio S.p.A./CN=Gestore PEC di Esempio S.p.A." -out "$csr"
  profile=$'keyUsage=critical,digitalSignature\nextendedKeyUsage=emailProtection\nsubjectAltName=email:posta-certificata@pec.example.it'
  signer sha512 sha512 "$profile"
  signer no-signing sha256 "${profile/digitalSignature/keyEncipherment}"
  signer no-email sha256 "${profile/emailProtection/clientAuth}"
  # 1.3.6.1.4.1.32473 is the private enterprise number reserved for documentation (RFC 5612).
  signer critical sha256 "$profile"$'\n1.3.6.1.4.1.32473.1=critical,ASN1:NULL'
  signer dns sha256 "$profile,DNS:mail.pec.example.it"
  rm -f "$csr"
fi

# CRLs of the test CA with chosen update times, carrying an authorityKeyIdentifier and a cRLNumber as AgID CA1's do,
# and a signer naming where its CRL is published. The index is written by hand to fix the revocation date.
if [[ ! -f pki/crls/current.der ]]; then
  mkdir -p pki/crls
  db=$(mktemp -d)
  # crl NAME ISSUER THIS_UPDATE NEXT_UPDATE [INDEX] [EXTENSION]
  crl() {
    printf '%s' "${5:+$5$'\n'}" > "$db/index.txt"
    printf '01\n' > "$db/crlnumber"
    openssl ca -gencrl -batch -cert "pki/$2.pem" -keyfile "pki/$2.key" -crl_lastupdate "$3" -crl_nextupdate "$4" \
      -config <(printf '[ca]\ndefault_ca=test\n[test]\ndatabase=%s/index.txt\ncrlnumber=%s/crlnumber\ndefault_md=sha256\ncrl_extensions=ext\n[ext]\nauthorityKeyIdentifier=keyid:always\n%s\n' "$db" "$db" "${6:-}") \
      -out "$db/crl.pem" 2>/dev/null
    openssl crl -in "$db/crl.pem" -outform DER -out "pki/crls/$1.der"
  }
  serial=$(openssl x509 -in pki/provider.pem -noout -serial | cut -d= -f2)
  end=$(date -u -d "$(openssl x509 -in pki/provider.pem -noout -enddate | cut -d= -f2)" +%Y%m%d%H%M%SZ)
  revoked=$(printf 'R\t%s\t270101000000Z,keyCompromise\t%s\tunknown\t/CN=Gestore PEC di Esempio S.p.A.\n' "$end" "$serial")
  crl current ca 261201000000Z 21261001000000Z
  crl revoked ca 270201000000Z 21261001000000Z "$revoked"
  crl stale ca 270201000000Z 270202000000Z
  crl after-expiry ca 21270101000000Z 21280101000000Z
  crl before-ca ca 260101000000Z 21261001000000Z
  crl critical ca 261201000000Z 21261001000000Z '' '1.3.6.1.4.1.32473.2=critical,ASN1:NULL'
  crl other-ca root 261201000000Z 21261001000000Z
  # Issued after current.der and stale since, revoking the provider, so the older current.der cannot hide it.
  crl stale-revoked ca 270201000000Z 270301000000Z "$revoked"
  csr=$(mktemp)
  openssl req -new -key pki/provider.key \
    -subj "/C=IT/ST=Roma/L=Roma/O=Gestore PEC di Esempio S.p.A./CN=Gestore PEC di Esempio S.p.A." -out "$csr"
  profile=$'keyUsage=critical,digitalSignature\nextendedKeyUsage=emailProtection\nsubjectAltName=email:posta-certificata@pec.example.it'
  # Two URLs to fetch the CRL from, beside a directory name and a name relative to the CA, which are no URLs.
  points=$'crlDistributionPoints=http,ldap,directory,relative\n[http]\nfullname=URI:http://crl.pec.example.it/CRL\n[ldap]\nfullname=URI:ldap://crl.pec.example.it/cn=PEC%20Test%20CA1\n[directory]\nfullname=dirName:directory_name\n[directory_name]\nCN=PEC Test CA1 CRL\n[relative]\nrelativename=relative_name\n[relative_name]\nCN=CRL1'
  openssl x509 -req -sha256 -in "$csr" -CA pki/ca.pem -CAkey pki/ca.key -set_serial 300 \
    -not_before "$not_before" -not_after "$not_after" \
    -extensions ext -extfile <(printf '[ext]\n%s\n%s\n' "$profile" "$points") \
    -outform DER -out pki/signers/distribution-points.der 2>/dev/null
  # RFC 5280 §4.1.2.5 gives a certificate with no well-defined expiration this notAfter.
  openssl x509 -req -sha256 -in "$csr" -CA pki/ca.pem -CAkey pki/ca.key -set_serial 301 \
    -not_before "$not_before" -not_after 99991231235959Z \
    -extfile <(printf '%s\n' "$profile") -outform DER -out pki/signers/no-expiry.der 2>/dev/null
  # The test CA re-issued with a keyUsage that allows certificates but not CRLs (RFC 5280 §6.3.3).
  openssl req -new -key pki/ca.key -subj "/C=IT/L=Roma/O=PEC Test CA/CN=PEC Test CA1" -out "$csr"
  openssl x509 -req -sha256 -in "$csr" -CA pki/root.pem -CAkey pki/root.key -set_serial 302 -days 36500 \
    -extfile <(printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign\nextendedKeyUsage=emailProtection\n') \
    -outform DER -out pki/anchors/no-crl-sign.der 2>/dev/null
  rm -rf "$db" "$csr"
fi

crlf() { sed 's/\r\{0,1\}$/\r/'; }

# build NAME HEADERS SUBJECT BODY DATICERT ORIGINAL ORIGINAL_NAME
# HEADERS are the PEC headers before Subject, one per line. DATICERT, ORIGINAL and ORIGINAL_NAME may be empty.
build() {
  local name=$1 headers=$2 subject=$3 body=$4 daticert=$5 original=$6 original_name=$7
  local inner
  inner=$(mktemp)
  {
    printf 'Content-Type: multipart/mixed; boundary="pec-inner"\n\n'
    printf -- '--pec-inner\nContent-Type: text/plain; charset="iso-8859-1"\nContent-Transfer-Encoding: quoted-printable\n\n%s\n' "$body"
    if [[ -n $daticert ]]; then
      printf -- '--pec-inner\nContent-Type: application/xml; name="daticert.xml"\nContent-Disposition: inline; filename="daticert.xml"\nContent-Transfer-Encoding: base64\n\n'
      base64 -w 76 "daticert/$daticert"
    fi
    if [[ -n $original ]]; then
      if [[ -n $original_name ]]; then
        printf -- '--pec-inner\nContent-Type: message/rfc822; name="%s"\nContent-Disposition: inline; filename="%s"\n\n' "$original_name" "$original_name"
      else
        printf -- '--pec-inner\nContent-Type: message/rfc822\nContent-Disposition: inline\n\n'
      fi
      # The line ending before a boundary belongs to the delimiter (RFC 2046), so one more keeps the message's own.
      tr -d '\r' < "original/$original"
      printf '\n'
    fi
    printf -- '--pec-inner--\n'
  } | crlf > "$inner"
  {
    printf '%s\nSubject: %s\n' "$headers" "$subject" | crlf
    openssl smime -sign -md sha256 -in "$inner" -signer pki/provider.pem -inkey pki/provider.key -certfile pki/ca.pem -crlfeol
  } > "messages/$name"
  rm -f "$inner"
}

RECEIPT='Date: Sun, 8 Nov 2026 10:15:00 +0100
From: posta-certificata@pec.example.it
To: mario.rossi@pec.example.it
Message-ID: <opec001.20261108101500.00001.01.1.%s@pec.example.it>
X-Riferimento-Message-ID: <20261108101458.0001@client.example.it>'
receipt() { printf "$RECEIPT\n%s" "$1" "$2"; }

build acceptance.eml "$(receipt 2 'X-Ricevuta: accettazione')" 'ACCETTAZIONE: Invio fattura 00012' \
  'Ricevuta di accettazione
Il giorno 08/11/2026 alle ore 10:15:00 (+0100) il messaggio
"Invio fattura 00012" proveniente da "mario.rossi@pec.example.it"
ed indirizzato a:
ufficio.fatture@pec.example.it ("posta certificata")
info@example.com ("posta ordinaria")
=E8 stato accettato dal sistema ed inoltrato.
Identificativo messaggio: opec001.20261108101500.00001.01.1.1@pec.example.it' acceptance.xml '' ''

build non-acceptance-virus.eml "$(receipt 3 $'X-Ricevuta: non-accettazione\nX-VerificaSicurezza: errore')" 'AVVISO DI NON ACCETTAZIONE PER VIRUS: Invio fattura 00012' \
  'Errore nell=27accettazione del messaggio per presenza di virus
Il giorno 08/11/2026 alle ore 10:15:00 (+0100) nel messaggio
"Invio fattura 00012" proveniente da "mario.rossi@pec.example.it"
ed indirizzato a:
ufficio.fatture@pec.example.it
=E8 stato rilevato un problema di sicurezza Eicar-Test-Signature.
Il messaggio non =E8 stato accettato.
Identificativo messaggio: opec001.20261108101500.00001.01.1.1@pec.example.it' non-acceptance-virus.xml '' ''

build taken-in-charge.eml "$(receipt 4 'X-Ricevuta: presa-in-carico')" 'PRESA IN CARICO: Invio fattura 00012' \
  'Ricevuta di presa in carico
Il giorno 08/11/2026 alle ore 10:15:00 (+0100) il messaggio
"Invio fattura 00012" proveniente da "mario.rossi@pec.example.it"
ed indirizzato a:
ufficio.fatture@pec.example.it
=E8 stato accettato dal sistema.
Identificativo messaggio: opec001.20261108101500.00001.01.1.1@pec.example.it' taken-in-charge.xml '' ''

build delivery-full.eml "$(receipt 5 'X-Ricevuta: avvenuta-consegna')" 'CONSEGNA: Invio fattura 00012' \
  'Ricevuta di avvenuta consegna
Il giorno 08/11/2026 alle ore 10:15:00 (+0100) il messaggio
"Invio fattura 00012" proveniente da "mario.rossi@pec.example.it"
ed indirizzato a "ufficio.fatture@pec.example.it"
=E8 stato consegnato nella casella di destinazione.
Identificativo messaggio: opec001.20261108101500.00001.01.1.1@pec.example.it' delivery-full.xml certified.eml postacert.eml

build delivery-summary.eml "$(receipt 6 'X-Ricevuta: avvenuta-consegna')" 'CONSEGNA: Invio fattura 00012' \
  'Ricevuta sintetica di avvenuta consegna
Il giorno 08/11/2026 alle ore 10:15:00 (+0100) il messaggio
"Invio fattura 00012" proveniente da "mario.rossi@pec.example.it"
ed indirizzato a "ufficio.fatture@pec.example.it"
=E8 stato consegnato nella casella di destinazione.
Identificativo messaggio: opec001.20261108101500.00001.01.1.1@pec.example.it' delivery-summary.xml '' ''

# Short receipts for a plain, a signed and an encrypted original (§6.5.2.2). The originals already carry the
# .hash parts a provider writes, so original/attachments.eml is the message the sender kept.
SHORT_BODY='Ricevuta breve di avvenuta consegna
Il giorno 08/11/2026 alle ore 10:15:00 (+0100) il messaggio
"Invio fattura 00012" proveniente da "mario.rossi@pec.example.it"
ed indirizzato a "ufficio.fatture@pec.example.it"
=E8 stato consegnato nella casella di destinazione.
Identificativo messaggio: opec001.20261108101500.00001.01.1.1@pec.example.it'
build delivery-short.eml "$(receipt 10 'X-Ricevuta: avvenuta-consegna')" 'CONSEGNA: Invio fattura 00012' \
  "$SHORT_BODY" delivery-short.xml short.eml postacert.eml
build delivery-short-signed.eml "$(receipt 11 'X-Ricevuta: avvenuta-consegna')" 'CONSEGNA: Invio fattura 00012' \
  "$SHORT_BODY" delivery-short.xml short-signed.eml postacert.eml
build delivery-short-encrypted.eml "$(receipt 12 'X-Ricevuta: avvenuta-consegna')" 'CONSEGNA: Invio fattura 00012' \
  "$SHORT_BODY" delivery-short.xml encrypted.eml postacert.eml
# A short receipt that keeps in place an attachment named only by its Content-Type, as Aruba does.
build delivery-short-kept.eml "$(receipt 14 'X-Ricevuta: avvenuta-consegna')" 'CONSEGNA: Invio fattura 00012' \
  "$SHORT_BODY" delivery-short.xml short-kept.eml postacert.eml
# A short receipt hashing a text attachment with LF line ends, as OpenPEC does, where the canonical form is CRLF.
build delivery-short-lf.eml "$(receipt 15 'X-Ricevuta: avvenuta-consegna')" 'CONSEGNA: Invio fattura 00012' \
  "$SHORT_BODY" delivery-short.xml short-lf.eml postacert.eml
# A full receipt whose original carries the sender's own attachment named .hash, which is no SHA-1.
build delivery-full-user-hash.eml "$(receipt 13 'X-Ricevuta: avvenuta-consegna')" 'CONSEGNA: Invio fattura 00012' \
  "${SHORT_BODY/Ricevuta breve di/Ricevuta di}" delivery-full.xml user-hash.eml postacert.eml

build delivery-error.eml "$(receipt 7 'X-Ricevuta: errore-consegna')" 'AVVISO DI MANCATA CONSEGNA: Invio fattura 00012' \
  'Avviso di mancata consegna
Il giorno 08/11/2026 alle ore 10:15:00 (+0100) nel messaggio
"Invio fattura 00012" proveniente da "mario.rossi@pec.example.it"
e destinato all=27utente "ufficio.fatture@pec.example.it"
=E8 stato rilevato un errore 5.1.1 - Utente non riconosciuto.
Il messaggio =E8 stato rifiutato dal sistema.
Identificativo messaggio: opec001.20261108101500.00001.01.1.1@pec.example.it' delivery-error.xml '' ''

build timeout-warning.eml "$(receipt 8 'X-Ricevuta: preavviso-errore-consegna')" 'AVVISO DI MANCATA CONSEGNA PER SUP. TEMPO MASSIMO: Invio fattura 00012' \
  'Avviso di mancata consegna
Il giorno 08/11/2026 alle ore 10:15:00 (+0100) il messaggio
"Invio fattura 00012" proveniente da "mario.rossi@pec.example.it"
e destinato all=27utente "ufficio.fatture@pec.example.it"
non e stato consegnato nelle prime dodici ore dal suo invio.
Identificativo messaggio: opec001.20261108101500.00001.01.1.1@pec.example.it' timeout-warning.xml '' ''

build virus-detected.eml "$(receipt 9 $'X-Ricevuta: rilevazione-virus\nX-Mittente: mario.rossi@pec.example.it')" 'PROBLEMA DI SICUREZZA: Invio fattura 00012' \
  'Avviso di rilevazione virus informatico
Il giorno 08/11/2026 alle ore 10:15:00 (+0100) nel messaggio
"Invio fattura 00012" proveniente da "mario.rossi@pec.example.it"
e destinato all=27utente "ufficio.fatture@pec.example.it"
=E8 stato rilevato un problema di sicurezza Eicar-Test-Signature.
Identificativo messaggio: opec001.20261108101500.00001.01.1.1@pec.example.it' virus-detected.xml '' ''

build transport.eml 'Return-Path: <mario.rossi@pec.example.it>
Date: Sun, 8 Nov 2026 10:15:00 +0100
From: "Per conto di: mario.rossi@pec.example.it" <posta-certificata@pec.example.it>
Reply-To: mario.rossi@pec.example.it
To: ufficio.fatture@pec.example.it
Cc: info@example.com
Message-ID: <opec001.20261108101500.00001.01.1.1@pec.example.it>
X-Riferimento-Message-ID: <20261108101458.0001@client.example.it>
X-TipoRicevuta: completa
X-Trasporto: posta-certificata' 'POSTA CERTIFICATA: Invio fattura 00012' \
  'Messaggio di posta certificata
Il giorno 08/11/2026 alle ore 10:15:00 (+0100) il messaggio
"Invio fattura 00012" =E8 stato inviato da "mario.rossi@pec.example.it"
indirizzato a:
ufficio.fatture@pec.example.it
info@example.com
Il messaggio originale =E8 incluso in allegato.
Identificativo messaggio: opec001.20261108101500.00001.01.1.1@pec.example.it' transport.xml certified.eml postacert.eml

build transport-summary.eml 'Return-Path: <mario.rossi@pec.example.it>
Date: Sun, 8 Nov 2026 10:15:00 +0100
From: "Per conto di: mario.rossi@pec.example.it" <posta-certificata@pec.example.it>
Reply-To: mario.rossi@pec.example.it
To: ufficio.fatture@pec.example.it
Cc: info@example.com
Message-ID: <opec001.20261108101500.00001.01.1.1@pec.example.it>
X-Riferimento-Message-ID: <20261108101458.0001@client.example.it>
X-TipoRicevuta: sintetica
X-Trasporto: posta-certificata' 'POSTA CERTIFICATA: Invio fattura 00012' \
  'Messaggio di posta certificata
Il giorno 08/11/2026 alle ore 10:15:00 (+0100) il messaggio
"Invio fattura 00012" =E8 stato inviato da "mario.rossi@pec.example.it"
indirizzato a:
ufficio.fatture@pec.example.it
info@example.com
Il messaggio originale =E8 incluso in allegato.
Identificativo messaggio: opec001.20261108101500.00001.01.1.1@pec.example.it' transport-summary.xml certified.eml postacert.eml

build anomaly.eml 'Return-Path: <paolo.bianchi@example.com>
Date: Sun, 8 Nov 2026 09:30:05 +0100
From: "Per conto di: paolo.bianchi@example.com" <posta-certificata@pec.example.it>
Reply-To: paolo.bianchi@example.com
To: ufficio.fatture@pec.example.it
Message-ID: <20261108093000.4242@mail.example.com>
X-Trasporto: errore' 'ANOMALIA MESSAGGIO: Richiesta informazioni' \
  'Anomalia nel messaggio
Il giorno 08/11/2026 alle ore 09:30:05 (+0100) =E8 stato ricevuto
il messaggio "Richiesta informazioni" proveniente da "paolo.bianchi@example.com"
ed indirizzato a:
ufficio.fatture@pec.example.it
Tali dati non sono stati certificati per il seguente errore:
firma assente
Il messaggio originale =E8 incluso in allegato.' '' ordinary.eml ''
