# Solve NaCl wget install problem

## Problem statement

The NaCl install instructions http://nacl.cr.yp.to/install.html state:

> Here is how to download and compile NaCl:
>
>     wget https://hyperelliptic.org/nacl/nacl-20110221.tar.bz2

But when I do this on a Ubuntu 18.04LTS system, I get:

```console
$ wget https://hyperelliptic.org/nacl/nacl-20110221.tar.bz2
--2021-03-14 12:12:50--  https://hyperelliptic.org/nacl/nacl-20110221.tar.bz2
Resolving hyperelliptic.org (hyperelliptic.org)... 131.155.70.18
Connecting to hyperelliptic.org (hyperelliptic.org)|131.155.70.18|:443... connected.
ERROR: cannot verify hyperelliptic.org's certificate, issued by ‘CN=R3,O=Let's Encrypt,C=US’:
  Unable to locally verify the issuer's authority.
To connect to hyperelliptic.org insecurely, use `--no-check-certificate'.
$
```

I don't care to install crypto software using `--no-check-certificate`, so...

## Analysis

The problem is that `hyperelliptic.org` is not serving out the certificate chain for Let's Encrypt; so we have to fetch the intermediate certs and add them locally.

Please be aware, if you're following this, that you may need to change the certs that you're fetching, and that you will want to refer to [https://letsencrypt.org/certificates/][1] to find the proper certificates.

[1]: https://letsencrypt.org/certificates/

The error message says that it's the `R3` certificate. The [Let's Encrypt Hierarchy diagram][1] says that the chain is ISRG Root X1 -> R3. So we need to install those certificates locally.

## Procedure

You'll need to download the intermediate certificates. Use the following commands.

```bash
# edit the following setting if Hyperelliptical.org changes its cert chain
CERTS="isrgrootx1 lets-encrypt-r3"
sudo mkdir /usr/local/share/ca-certificates/letsencrypt.org
for iCert in $CERTS ; do
	sudo wget -O "/usr/local/share/ca-certificates/letsencrypt.org/${iCert}.crt" "https://letsencrypt.org/certs/${iCert}.pem"
done
sudo update-ca-certificates 
```

At the end, you should see something like:

```console
Updating certificates in /etc/ssl/certs...
rehash: skipping duplicate certificate in ISRG_Root_X1.pem
2 added, 0 removed; done.
Running hooks in /etc/ca-certificates/update.d...
done.
```

(Evidently I already had `IRSG_Root_X1`; the thing to look for is `2 added`, as this indicates that you've got the certificates correctly installed.)

## Testing

Re-enter the `wget` command:

```console
$ wget https://hyperelliptic.org/nacl/nacl-20110221.tar.bz2 
--2021-03-14 12:24:00--  https://hyperelliptic.org/nacl/nacl-20110221.tar.bz2
Resolving hyperelliptic.org (hyperelliptic.org)... 131.155.70.18
Connecting to hyperelliptic.org (hyperelliptic.org)|131.155.70.18|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 163415 (160K) [application/x-bzip2]
Saving to: ‘nacl-20110221.tar.bz2’

nacl-20110221.tar.bz2           100%[=====================================================>] 159.58K   543KB/s    in 0.3s

2021-03-14 12:24:00 (543 KB/s) - ‘nacl-20110221.tar.bz2’ saved [163415/163415]

$
```
