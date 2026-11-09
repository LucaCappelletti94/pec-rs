#!/usr/bin/env bash
# Recreates the throwaway test PKI and every signed message under messages/.
# Run from anywhere. Needs openssl 3.
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p pki messages
if [[ ! -f pki/provider.pem ]]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 36500 \
    -subj "/C=IT/O=PEC Test CA/CN=PEC Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout pki/ca.key -out pki/ca.pem 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/C=IT/O=Gestore PEC di Esempio S.p.A./CN=posta-certificata@pec.example.it/emailAddress=posta-certificata@pec.example.it" \
    -keyout pki/provider.key -out pki/provider.csr 2>/dev/null
  openssl x509 -req -in pki/provider.csr -CA pki/ca.pem -CAkey pki/ca.key -CAcreateserial -days 36500 \
    -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\nextendedKeyUsage=emailProtection\nsubjectAltName=email:posta-certificata@pec.example.it\n') \
    -out pki/provider.pem 2>/dev/null
  rm -f pki/provider.csr pki/ca.srl
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
    openssl smime -sign -in "$inner" -signer pki/provider.pem -inkey pki/provider.key -certfile pki/ca.pem -crlfeol
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
