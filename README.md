# Luzifer / vault-totp

`vault-totp` is a OneTimePassword generator working on the same protocol as the Google Authenticator app, just using Vault as its secret backend. This can be used for example if you have MFA tokens you sparely need and you don't want to have your authenticator app on your mobile phone cluttered.

## Usage

```bash
# vault write secret/otp/example secret=JBSWY3DPEHPK3PXP
Success! Data written to: secret/otp/example

# vault-totp secret/otp/example
058805 (Valid 11s)
```

For more options like `-1` (one-time print) or `-n` (hide time) see `vault-totp --help`.
