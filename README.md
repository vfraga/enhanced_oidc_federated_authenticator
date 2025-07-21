# Enhanced OIDC Authenticator for WSO2 IS 6.0.0

This project provides an `EnhancedOIDCAuthenticator`, a custom federated authenticator that extends the default `OpenIDConnectAuthenticator` in WSO2 Identity Server. It enhances the standard OIDC capabilities with two primary features:

1.  **Expanded Client Authentication:** Adds support for `private_key_jwt` and `client_secret_jwt`, enabling more secure, JWT-based client authentication methods at the token endpoint.
2.  **ID Token Decryption:** Introduces the capability to decrypt encrypted ID tokens (JWE) before they are processed by the Identity Server. This implementation uses the **same private key** that is configured for signing client assertions.

-----

## Deployment and Configuration

### Step 1: Deploy the Authenticator

Copy the compiled JAR file from the `<PROJECT_HOME>/target/` directory to the `<IS_HOME>/repository/components/dropins/` directory.

### Step 2: Prepare the Keystore

This authenticator loads a cryptographic key from a keystore. This single key is used for both:

* Signing client assertions when using the `private_key_jwt` method.
* Decrypting incoming ID tokens if they are encrypted.

Ensure the keystore file specified in `deployment.toml` contains the necessary private key and certificate.

### Step 3: Configure `deployment.toml`

Add the following configuration block to the `<IS_HOME>/repository/conf/deployment.toml` file. This defines the location of your keystore and the cryptographic algorithms your server supports.

```toml
# =================================================================================
# Custom Authenticator Configurations
# =================================================================================
[[authentication.custom_authenticator]]
name = "EnhancedOIDCAuthenticator"

# --- Keystore for Signing Assertions & Decrypting ID Tokens ---
parameters.signing_keystore_path = "${carbon.home}/repository/resources/security/wso2carbon.jks"
parameters.signing_keystore_password = "wso2carbon"
parameters.signing_key_alias = "wso2carbon"
parameters.signing_key_password = "wso2carbon"
parameters.signing_keystore_type = "JKS"

# --- Supported Algorithm Lists ---
# These values populate the dropdowns in the admin UI.
# Ensure the algorithms match the key type in your keystore.
parameters.token_endpoint_auth_signing_alg_values_supported = "RS256,RS384,RS512,PS256,PS384,PS512,ES256,ES384,ES512"
parameters.id_token_signing_alg_values_supported = "RS256,ES256"
parameters.id_token_encryption_alg_values_supported = "RSA-OAEP-256,RSA-OAEP,ECDH-ES+A128KW,ECDH-ES+A192KW,ECDH-ES+A256KW"
parameters.id_token_encryption_enc_values_supported = "A256GCM,A128GCM,A256CBC-HS512"
```

> **Note on Algorithms:** The cryptographic algorithms you configure for signing and encryption must belong to the same algorithm family as the key pair selected (e.g., RSA-based keys for `RS256`/`RSA-OAEP`, and EC-based keys for `ES256`/`ECDH-ES`).

### Step 4: Start the Server and Configure the IdP

1.  Start the WSO2 Identity Server.
2.  In the WSO2 Management Console, [create a new Identity Provider](https://is.docs.wso2.com/en/6.0.0/guides/identity-federation/add-idp/).
3.  Under the **Federated Authenticators** section, expand **Enhanced OIDC Authenticator** and provide the necessary configuration values. The dropdowns for algorithms will be populated based on your `deployment.toml` settings.
4.  [Configure a Service Provider](https://is.docs.wso2.com/en/6.0.0/guides/applications/local-outbound-auth-for-sp/) to use your newly created IdP for federated authentication.

-----

## Development and Troubleshooting

### Enabling Debug Logs

To see debug logs from this component, add a new logger to the `<IS_HOME>/repository/conf/log4j2.properties` file.

1.  **Define the logger:**

    ```properties
    logger.org-sample.name = org.sample
    logger.org-sample.level = DEBUG
    ```

2.  **Add it to the list of loggers:**

    ```properties
    loggers = ..., org-sample
    ```

### Remote Debugging

You can attach a remote debugger to the running WSO2 Identity Server instance.

1.  **Start the server in debug mode:**

    ```sh
    # On Linux/macOS
    sh <IS_HOME>/bin/wso2server.sh --debug 5005

    # On Windows
    <IS_HOME>\bin\wso2server.bat --debug 5005
    ```

    > The server startup will pause until a debugger connects.

2.  **Attach your IDE's debugger:**

   * Create a new "Remote JVM Debug" configuration in your IDE (IntelliJ, VSCode, Eclipse).
   * Set the host to `localhost` and the port to `5005`.
   * Add breakpoints in the code and start the debugging session. The server will resume its startup process.
