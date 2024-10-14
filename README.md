*14 october 2024*

**WORK IN PROGRESS**

# gosend
**gosend** is a command line SMTP client written in Go to send e-mails over STARTTLS or SSL/TLS. It supports plain text, HTML and attachments.

## Flag Options

- `-help`: Show flag options.

### Server

- `-server-file value`: Path to settings file.
- `-smtp-host value`: Hostname of SMTP server.
- `-smtp-port value`: TCP port of SMTP server.
- `-rootca value`: File path to X.509 certificate in PEM format for the Root CA when using a self-signed certificate on the mail server.

### Authentication

- `-auth-file value`: Path to authentication file.
- `-auth-method value`: Authentication method (STARTTLS, SSL/TLS).
- `-login string`: Login username.
- `-password string`: Login password.

### Message Header

- `-sender value`: Email address of sender.
- `-to value`: Recipient TO address. Comma separate multiple email addresses or use multiple `-to` options.
- `-cc value`: Recipient CC address. Comma separate multiple email addresses or use multiple `-cc` options.
- `-bcc value`: Recipient BCC address. Comma separate multiple email addresses or use multiple `-bcc` options.
- `-subject string`: Email subject.

### Message Body

- `-body-html string`: Body content in HTML.
- `-body-text string`: Body content in plain text. Add new lines as `\n`.
- `-attachment value`: File path to attachment. Comma separate multiple attachments or use multiple `-attachment` options.

### Notes

- No authentication is only supported for `localhost`.
- New lines in the `body-text` are supported by inserting `\n`in your text. These wil be converted to CR LF in your e-mail message.
- To send your e-mail to multiple recipients you can either use multiple `-to`options or a `-to`option with comma separated addresses.
- To send multiple attachments you can either use multiple `-attachment`options or a `-attachment`option with comma separated files.
- `-rootca`can be used when your mail server is using a self-signed certificate.
  - The X.509 certificate must be a PEM container file.
  - Use *Subject Alternative Name* (SAN) fields in your self-signed certificate. 

### Example

```bash
./gosend \
 -smtp-host mail.example.com
 -smtp-port 587
 -auth-method STARTTLS
 -login "your_username"
 -password "your_password"
 -sender sender@example.com \
 -to receiver1@mail.com -to "receiver2@mail.com, receiver2@mail.org" \
 -cc "copy@mail.com" \
 -subject "Your subject" \
 -body-text "Hi\n\nThis a plain text message." \
 -body-html "<h1>Hi</h1><p>This is a HTML message</p><img src=\"myimage.jpg\" alt=\"My image\">" \
 -attachment "images/myimage.jpg"
```

## Settings Files

With the flags `-server-file` and `-auth-file` you can point to a settings file which contains the desired settings for the server and authentication.

Supported flags are:
- `server-file`
- `smtp-host`
- `smtp-port`
- `rootca`
- `auth-file`
- `auth-method`
- `login`
- `password`

### Notes

- Use a `=`to separate the flag and its value. Spaces around the `=`are optional.
- Values may optionally surrounded by double quotes `" "`
- Flags given at the command line overrule the flags in the settings file.
- All suported flags may be used in both `-server-file` and `-auth-file`.

### Example

```ini
smtp-host="mail.example.com"
smtp-port=587
```
