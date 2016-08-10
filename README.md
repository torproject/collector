CollecTor -- The friendly data-collecting service in the Tor network
====================================================================

CollecTor fetches data from various nodes and services in the public
Tor network and makes it available to the world.

Verifying releases
------------------

Releases can be cryptographically verified to get some more confidence that
they were put together by a Tor developer.  The following steps explain the
verification process by example.

Download the release tarball and the separate signature file:

```
wget https://dist.torproject.org/collector/1.0.0/collector-1.0.0.tar.gz
wget https://dist.torproject.org/collector/1.0.0/collector-1.0.0.tar.gz.asc
```

Attempt to verify the signature on the tarball:

```
gpg --verify collector-1.0.0.tar.gz.asc
```

If the signature cannot be verified due to the public key of the signer
not being locally available, download that public key from one of the key
servers and retry:

```
gpg --keyserver pgp.mit.edu --recv-key 0x4EFD4FDC3F46D41E
gpg --verify collector-1.0.0.tar.gz.asc
```

If the signature still cannot be verified, something is wrong!

But note that even if it can be verified, you now only know that the
signature was made by the person claiming to own this key, which could be
anyone.  You'll need a trust path to the owner of this key in order to
trust this signature, but that's clearly out of scope here.  In short,
your best chance is to meet a Tor developer in real life and enter the web
of trust.

If you want to go one step further in the verification game, you can
verify the signature on the .jar files.

Print and then import the provided X.509 certificate:

```
keytool -printcert -file CERT
keytool -importcert -alias karsten -file CERT
```

Verify the signatures on the contained .jar files using Java's jarsigner
tool:

```
jarsigner -verify collector-1.0.0.jar
jarsigner -verify collector-1.0.0-sources.jar
```

