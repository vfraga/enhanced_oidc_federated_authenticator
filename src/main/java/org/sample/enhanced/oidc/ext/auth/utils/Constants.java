package org.sample.enhanced.oidc.ext.auth.utils;

import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;

public final class Constants {
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Enhanced OIDC Authenticator";
    public static final String AUTHENTICATOR_NAME = "EnhancedOIDCAuthenticator";

    public static final class OIDC {
        public static final String CLIENT_SECRET_POST = "client_secret_post";
        public static final String CLIENT_SECRET_BASIC = "client_secret_basic";
        public static final String CLIENT_SECRET_JWT = "client_secret_jwt";
        public static final String PRIVATE_KEY_JWT = "private_key_jwt";

        public static final String CLIENT_ASSERTION_TYPE = "client_assertion_type";
        public static final String CLIENT_ASSERTION = "client_assertion";
        public static final String JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

        public static final String[] CLIENT_AUTH_METHODS = {
                CLIENT_SECRET_POST,
                CLIENT_SECRET_BASIC,
                CLIENT_SECRET_JWT,
                PRIVATE_KEY_JWT
        };
    }

    public static final String COMMA_SEPARATOR_REGEX = "\\s*,\\s*";

    public static final class AuthenticatorConfig {
        // UI-based (runtime) properties
        public static final String CLIENT_ID = IdentityApplicationConstants.Authenticator.OIDC.CLIENT_ID;
        public static final String CLIENT_SECRET = IdentityApplicationConstants.Authenticator.OIDC.CLIENT_SECRET;
        public static final String OAUTH_AUTHORIZATION_ENDPOINT_URL = IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_AUTHZ_URL;
        public static final String OAUTH_TOKEN_ENDPOINT_URL = IdentityApplicationConstants.Authenticator.OIDC.OAUTH2_TOKEN_URL;
        public static final String CALLBACK_URL = IdentityApplicationConstants.Authenticator.OIDC.CALLBACK_URL;
        public static final String USERINFO_URL = IdentityApplicationConstants.Authenticator.OIDC.USER_INFO_URL;
        public static final String IS_USERID_IN_CLAIMS = IdentityApplicationConstants.Authenticator.OIDC.IS_USER_ID_IN_CLAIMS;
        public static final String SCOPES = "Scopes";
        public static final String ADDITIONAL_QUERY_STRING_PARAMETERS = "commonAuthQueryParams";
        public static final String SELECTED_CLIENT_AUTH = "SelectedClientAuthMethod";
        public static final String JWT_AUDIENCE = "Audience";
        public static final String JWT_EXPIRY = "JwtExpiry";
        public static final String IS_PUBLIC_CLIENT = "IsPublicClient";
        public static final String IS_ID_TOKEN_ENCRYPTED = "IsIdTokenEncrypted";
        public static final String JWKS_ENDPOINT_URL = "JwksEndpointUrl";
        public static final String ID_TOKEN_ENC_ALG = "IdTokenEncryptionAlgorithm";
        public static final String ID_TOKEN_SIGN_ALG = "IdTokenSignatureAlgorithm";
        public static final String JWT_ASSERTION_SIGN_ALG = "JwtAssertionSignatureAlgorithm";

        // deployment.toml properties
        public static final String SIGNING_KEYSTORE_PATH = "signing_keystore_path";
        public static final String SIGNING_KEYSTORE_PASSWORD = "signing_keystore_password";
        public static final String SIGNING_KEY_ALIAS = "signing_key_alias";
        public static final String SIGNING_KEY_PASSWORD = "signing_key_password";
        public static final String SIGNING_KEYSTORE_TYPE = "signing_keystore_type";
        public static final String TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED = "token_endpoint_auth_signing_alg_values_supported";
        public static final String ID_TOKEN_ENCRYPTION_ALG_VALUES_SUPPORTED = "id_token_encryption_alg_values_supported";
        public static final String ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED = "id_token_signing_alg_values_supported";
    }
}
