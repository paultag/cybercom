cyber-authorized-keys(1) -- dynamically output an authorized-keys file for a user
=================================================================================

`cyber-authorized-keys` will dynamically output an authorized-keys file for
a user.

Internally, `cyber-authorized-keys` will query the CYBERCOM server, and output
an ssh public key line for each matching Entity.

Mapping a User to an Email
--------------------------

Naturally, the process of mapping a user to an email is not straight forward,
since usernames may not match mail localparts, or email accounts may be
hosted on domains that are not operated by the same organization.

As a workaround, `cyber-authorized-keys` will call `getpwuid(3)` on the user,
and fetch the `pw_gecos` field from the `passwd` struct. The `gecos` entry will
be split, and the `other` field will be used as the email.

To set the email for a user on a standard Linux machine using local PAM unix
authentication `chfn(1)` with the `--other` flag will set this field. For
other setups, such as active directory or custom PAM modules, the implementation
will dictate how the `gecos` field is populated.

```
$ # Set the email for `paultag` to `paultag@example.com`
$ sudo chfn paultag --other paultag@example.com`
```

Setting cyber-authorized-keys in sshd_config
--------------------------------------------

In your friendly local `/etc/ssh/sshd_config`, add the following lines:

```
AuthorizedKeysCommand /usr/local/bin/cyber-authorized-keys --server=cybercom.example.tld:2611 %u
AuthorizedKeysCommandUser nobody
```
