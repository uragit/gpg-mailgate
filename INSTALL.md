INSTALLING GPG-MAILGATE
=======================

GPG-mailgate is a mail filter, called by postfix, to encrypt email if
a GPG public key is available.


To install
----------




 1. Ensure that GPG is installed and configured.
 2. Create a location to store a GPG directory for holding public keys.  You can use
    the `--homedir dir` argument to tell GPG to use a particular location for its keyring.
    See `Note 1` below for a possible setup.

    (Create a new keyring with only public keys; don't just use your own keyring
    containing your own private key, even if it is encrypted with a passphrase; it's
    an additional risk to let that key be accessible unecessarily. )

    These instructions assume you already have a suitable PGP configuration.
    Info on creating a GPG keyring is beyond the scope of these instructions
    but you can start at http://www.gnupg.org/gph/en/manual.html

    Make sure any public keys for your potential recipients are
    stored in the GPG directory you use.
 3. Configure `/etc/gpg-mailgate.conf` based on the provided
    `gpg-mailgate.conf.sample`
 4. Place `gpg-mailgate.py` in `/usr/local/bin/`
 5. Place the provided `GnuPG` directory in `/usr/lib/python2.7/` (replace 2.7 with your
    Python version)
 6. Add the following to `/etc/postfix/main.cf`

        content_filter = gpg-mailgate

 7. Add the following to the end of `/etc/postfix/master.cf`

        gpg-mailgate    unix    -   n   n   -   -   pipe
            flags= user=nobody argv=/usr/local/bin/gpg-mailgate.py ${recipient}

        127.0.0.1:10028 inet    n   -   n   -   10  smtpd
            -o content_filter=
            -o receive_override_options=no_unknown_recipient_checks,no_header_body_checks
            -o smtpd_helo_restrictions=
            -o smtpd_client_restrictions=
            -o smtpd_sender_restrictions=
            -o smtpd_recipient_restrictions=permit_mynetworks,reject
            -o mynetworks=127.0.0.0/8
            -o smtpd_authorized_xforward_hosts=127.0.0.0/8
 8. Restart postfix.
 9. Test/troubleshoot.

    Send an email via postfix to an account you control, with a known public key in
    the keyring from `Step 2`.  The email should arrive encrypted.  If not, check
    the logfile specified in config file, /etc/gpg-mailgate.conf.  If
    problems exist, try setting 'verbose = yes' in the config file to get
    more verbose logging.


## Note 1

It is possible to create a dedicated user to store the PGP public keys with
these example commands:

    useradd -s /bin/false -d /var/gpg -M gpgmap
    mkdir -p /var/gpg/.gnupg
    chown -R gpgmap /var/gpg
    chmod 700 /var/gpg/.gnupg
    sudo -u gpgmap /usr/bin/gpg --import /home/youruser/public.key --homedir=/var/gpg/.gnupg

  - Replace `/home/youruser/public.key` with the location of your public key
  - `/home/youruser/public.key` can be deleted after importation
  - Confirm that it's working: `sudo -u gpgmap /usr/bin/gpg --list-keys --homedir=/var/gpg/.gnupg`
  - Use `keyhome = /var/gpg/.gnupg` in `gpg-mailgate.conf`
