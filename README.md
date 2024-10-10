# gosend

Work in progress

- `-help`: Show flag options.

- `-server-settings-file value`: Path to settings file.
- `-smtp-host value`: Hostname of SMTP server.
- `-smtp-port value`: TCP port of SMTP server.
- `-rootca value`: X.509 certificate in PEM format for the Root CA when using a self-signed certificate on the mail server.

- `-auth-file value`: Path to authentication file.
- `-auth-method value`: Authentication method (STARTTLS, SSL/TLS).
- `-login string`: Login username.
- `-password string`: Login password.

- `-sender value`: Email address of sender.
- `-to value`: Recipient TO address. Comma separate multiple email addresses or use multiple to options.
- `-cc value`: Recipient CC address. Comma separate multiple email addresses or use multiple cc options.
- `-bcc value`: Recipient BCC address. Comma separate multiple email addresses or use multiple bcc options.
- `-subject string`: Email subject.

- `-body-html string`: Body content in HTML.
- `-body-text string`: Body content in plain text.
- `-attachment value`: File path to attachment. Comma separate multiple attachments or use multiple attachment options.

