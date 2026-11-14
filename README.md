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
    "redirect_url": "https://<mythic-domain>:7443/auth_acs/oidc/oidc",
    "mtls_cert_file": "",
    "mtls_key_file": "",
    "mtls_ca_file": ""
}
```

`issuer` - The base URL of the OpenID Connect provider.  
`client_id` - The unique identifier assigned to your Mythic application by the OIDC provider.  
`client_secret` - A secret key issued alongside the `client_id`.  
`redirect_url` - The callback URL where the OIDC provider will send the user after authentication. Must be `https://<mythic-domain>:7443/auth_acs/oidc/oidc`.  
`mtls_cert_file` - Optional client certificate filename for mTLS.  
`mtls_key_file` - Optional client private key filename for mTLS.  
`mtls_ca_file` - Optional CA bundle filename used to trust the OIDC provider.  

Once the configuration is saved, users can log in to Mythic via the configured OIDC provider.

> **Note:** The user must already exist in Mythic, and their Mythic email address must match the one registered with the OIDC provider.

## mTLS

If the OIDC provider requires mutual TLS (or a private certificate authority), upload the certificate files through the auth container's file browser and reference their filenames from `config.json`.

1. Install the auth container.
2. Open the provider's file browser using the paperclip icon, then upload:
   - the client certificate, for example `oidc_mtls_client.pem`
   - the client private key, for example `oidc_mtls_client.key`
   - optionally, the CA bundle used to trust the provider, for example `oidc_mtls_ca.pem`
3. Edit `config.json` and set the corresponding filenames:

```json
{
    "issuer": "https://oidc.example.com",
    "client_id": "<client-id>",
    "client_secret": "<client-secret>",
    "redirect_url": "https://<mythic-domain>:7443/auth_acs/oidc/oidc",
    "mtls_cert_file": "oidc_mtls_client.pem",
    "mtls_key_file": "oidc_mtls_client.key",
    "mtls_ca_file": "oidc_mtls_ca.pem"
}
```

The fields are optional:

- **All empty** – mTLS is disabled and behaviour is unchanged.
- **`mtls_ca_file` only** – the provider is trusted using only the uploaded CA bundle.
- **`mtls_cert_file` + `mtls_key_file`** – mutual TLS is used, with or without a custom CA.
- **Only one of the certificate/key fields set** – treated as a configuration error. Both are required for client authentication.

The files are read from the container's runtime directory at login, so changes take effect without restarting the container. Filenames must be plain filenames (no directories), matching the files shown in the file browser.

> **Note:** Files uploaded through the file browser live inside the container. Re-upload them if the container is recreated, for example during an update.

> **Note:** When `mtls_ca_file` is set, it replaces the system trust store for OIDC requests. Append any public roots you also need to the uploaded bundle.

![](.assets/step-3.png)
