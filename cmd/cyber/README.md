cyber(1) -- cybercom client
===========================

SYNOPSIS
--------

`cyber` [global options] <command> [command options] [arguments...]

DESCRIPTION
-----------

`cyber` is the standard CYBERCOM implementation, feature complete for
small to moderately sized deployments. This command can read and write
x509 Certificates onto the Filesystem or a Yubikey, as well as preform
management functions, such as Certificate issuance, revocation and
new entity approval.

Commands
--------

`whoami` [--cert]  
Query the cyber store Certificate, and if initialized, connect to the cyber
server, and validate our entity information, outputting our entity state,
email, and our ID.

`init`  
Initalize a cyber store by generating a new key, prompting for personal information
to be sent to the server encapsulated as an x509 CSR, and register that CSR with
the cybercom CA server.

`renew`  
Request the cybercom CA server issue the client a new Certificate. Individual
CA servers may have different policy, but this usually requires the client to
be authenticated, and using an acitve and valid Certificate shortly before
the not after date.

`get` id...  
Get information regarding an Entity by their ID, including their active Certificate.

`ls` [--csr] [--email=name@domain.tls] [--state=state]  
List known entities, their state, email and Common Name. The output can be
limited by passing the `--email` flag, or `--state` flag. The default states
are `APPROVED,PENDING,ONEOFF`.

`certificates` id...  
Get all known Certificates for an Entity by their ID. Some small amount of
metadata will be output before each Certificate.

`import`  
Import a Certificate into the Cyber store, directly. No checking is done to
ensure the public key matches, and importing the wrong Certificate may cause
any number of unpredictable things to happen. This is generally used during
a manual initialization workflow, and hopefully only once.

`ping`  
Ensure connectivity to the cybercom CA server, and get the remote CA name.

`ca`  
Return the pool of CA Certificates that the cybercom CA server knows about.
This is useful, since the cybercom CA TLS connection for RPC should be a
publically trusted Certificate, and there may be multiple cybercom CA servers
that know about the other client CAs. This may also be usful to transition
the CA Certificate near its expiration.

`certificate-by-serial`  
Get a Certificate by the hex encoding of the Certifciate's Serial Number.

`issue-certificate` id...  
Issue a new Certificate for the given Entity. This is useful if the client
does not have an existing Certificate, or if their Certificate has expired.

`set-state` id state  
Alter the Entity to set Entity denoted by their ID to the state given. Valid
states include `approved`, `rejected`, `revoked`, `oneoff`, or `pending`.

`set-longevity` id longevity  
Alter the Entity to set the Entity denoted by their ID to request that all
Certificates be issued with a longevity of `longevity. This can be useful to
special-case long-lived Certificates without changing the global default.

`set-expiry` id expiry
Alter the Entity to set the Entity denoted by their ID to refuse to issue new
Certificates that are valid after the expiration date.

`sign-csr` [--longevity=longevity] [--oneoff] csr...  
Register the given CSRs, approve them (or set it to `oneoff` if `--oneoff` is
set), issue a new Certificate, and output that Certificate to stdout.

`ssh-keygen` id...  
Output the Entity's public key in ssh authorized keys format, allowing an
Entity's store to be used to grant ssh access to machines over the network.

`remind` id...  
Output the NotAfter date of each Entity in remind(1) format, allowing for
reminders before a Certificate expires.

AUTHOR
------

Paul Tagliamonte <paultag@gmail.com>

SEE ALSO
--------

cyber-authorized-keys(1), openssl(1), cyberd(1), remind(1)
