#!/bin/sh

set -x

MAIL_SERVER=$(dig -t MX $1 +short | cut -d ' ' -f2 | head -n 1)
openssl s_client -connect $MAIL_SERVER:25 -starttls smtp > $1
