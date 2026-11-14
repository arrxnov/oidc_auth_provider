# oidc_auth_provider

oidc_auth_provider is an authentication container that provides support for OpenID Connect (OIDC) authentication to Mythic.

## Installation

```
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/oidc_auth_provider
```

## Configuration

After installing the provider, navigate to Installed Services → AUTH tab, then click the paperclip icon:

![](.assets/step-1.png)

Edit `config.json` file:

![](.assets/step-2.png)

Example configuration:

```json
{
    "issuer": "https://oidc.example.com",
    "client_id": "<client-id>",
    "client_secret": "<client-secret>",
    "redirect_url": "https://<mythic-domain>:7443/auth_acs/oidc/oidc"
}
```

`issuer` - The base URL of the OpenID Connect provider.  
`client_id` - The unique identifier assigned to your Mythic application by the OIDC provider.  
`client_secret` - A secret key issued alongside the `client_id`.  
`redirect_url` - The callback URL where the OIDC provider will send the user after authentication. Must be `https://<mythic-domain>:7443/auth_acs/oidc/oidc`.  

Once the configuration is saved, users can log in to Mythic via the configured OIDC provider.

> **Note:** The user must already exist in Mythic, and their Mythic email address must match the one registered with the OIDC provider.

## mTLS

If the OIDC provider requires mutual TLS (or a private certificate authority), upload the files through the Mythic UI under **Files → Uploads** using exactly these names:

| File | Purpose |
| --- | --- |
| `oidc_mtls_client.pem` | Client certificate (PEM) |
| `oidc_mtls_client.key` | Client private key (PEM) |
| `oidc_mtls_ca.pem` | CA bundle used to trust the provider (PEM) |

The files are optional and are read from Mythic's file store at login, so no files need to be mounted and `config.json` does not change:

- **None present** – mTLS is disabled and behaviour is unchanged.
- **CA only** – the provider is trusted using only the uploaded CA bundle.
- **Client certificate + key (with or without CA)** – mutual TLS is used. Uploading only one half of the keypair is treated as an error.

The provider checks for updated uploads at most once per minute. To rotate a certificate or CA, upload a new file with the same name; the container picks it up on the next login without a restart. Deleted files are no longer used.

> **Note:** When a CA bundle is uploaded, it replaces the system trust store for OIDC requests. Append any public roots you also need to the uploaded bundle.

![](.assets/step-3.png)
