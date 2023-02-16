# Mail Mesh

Full credit for the initial regular expressions and rule work goes to Cory: [Handling inbound email on Fastmail](https://blog.coryd.dev/2023/01/workflows-handling-inbound-email-on-fastmail-with-regular-expressions)

## How to use

Use in your Sieve rules. As this was designed for Fastmail, these rules are assumed to be included: 

``` sieve
require ["fileinto", "reject", "vacation", "imap4flags", "notify", "envelope", "body", "relational", "regex", "subaddress", "copy", "mailbox", "mboxmetadata", "servermetadata", "date", "index", "comparator-i;ascii-numeric", "variables", "editheader", "duplicate", "vacation-seconds"];
```

## Customization

This is designed to forward to a reading app, as well as a package tracking app. Adjust the forwarding destination to fit your needs.