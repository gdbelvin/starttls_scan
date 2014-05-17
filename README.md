starttls_scan
=============

Survey the internet's mail servers to find market penetration of STARTTLS

Invocation:
zmap -p 25 -o - | scanner -database=sqlite3:/path/to/new/db/file 

