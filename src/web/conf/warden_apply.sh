#!/bin/bash
# This file is from the Warden project.
# https://warden.cesnet.cz/cs/downloads

key=key.pem
csr=csr.pem
cert=cert.pem
result=${TMPDIR:-${TMP:-/tmp}}/cert.$$.$RANDOM
config=${TMPDIR:-${TMP:-/tmp}}/conf.$$.$RANDOM
if [ "$1" == "--cacert" ]; then
  cacert="--cacert $2"
  shift
  shift
fi
url="$1"
client="$2"
password="$3"
incert="$3"
inkey="$4"

trap 'rm -f "$config $result"' INT TERM HUP EXIT

function flee { echo -e "$1"; exit $2; }

[ -z "$client" -o -z "$password" ] && flee "Usage: ${0%.*} [--cacert CERT] url client.name password\n       ${0%.*} [--cacert CERT] url client.name cert_file key_file" 255

url="${url%/}/getCert"

for n in openssl curl; do
    command -v "$n" 2>&1 >/dev/null || flee "Haven't found $n binary." 251
done
for n in "$csr" "$key" "$cert"; do
    [ -e "$n" ] && flee "$n already exists, I won't overwrite, move them away first, please." 254
done
for n in "$result" "$config"; do
    touch "$n" || flee "Error creating temporary file ($n)." 253
done

echo -e "default_bits=2048\ndistinguished_name=rdn\nprompt=no\n[rdn]\ncommonName=dummy" > "$config"

openssl req -new -nodes -batch -keyout "$key" -out "$csr" -config "$config" || flee "Error generating key/certificate request." 252

if [ -z "$inkey" ]; then
    curl --progress-bar $cacert --request POST --data-binary '@-' "$url?name=$client&password=$password" < "$csr" > "$result"
else
    # local cert file name may be interpreted as a "nickname", add "./" to force interpretation as a file
    if [[ ! "$incert" =~ "/" ]]; then
        incert="./$incert"
    fi
    curl --progress-bar $cacert --request POST --data-binary '@-' --cert "$incert" --key "$inkey" "$url?name=$client" < "$csr" > "$result"
fi

case $(<$result) in '-----BEGIN CERTIFICATE-----'*)
    mv "$result" "$cert"
    flee "Succesfully generated key ($key) and obtained certificate ($cert)." 0
esac

flee "$(<$result)\n\nCertificate request failed. Please save all error messages for communication with registration authority representative." 252
