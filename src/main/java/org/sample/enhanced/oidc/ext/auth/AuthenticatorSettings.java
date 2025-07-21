package org.sample.enhanced.oidc.ext.auth;

import org.sample.enhanced.oidc.ext.auth.utils.Constants;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.Property;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Provides the configuration properties for the JWT Bearer OIDC Authenticator.
 * Keeping this here since the method is quite long.
 */
public final class AuthenticatorSettings {
    private AuthenticatorSettings () {
        // Prevent instantiation
    }

    public static List<Property> getConfigurationProperties(final Map<String, String> authenticatorParams) {
        final List<Property> configProperties = new ArrayList<>();
        int displayOrder = 0;  // Using pre-increment (++n) to set display order

        // Group 1: Core OIDC Endpoints
        final Property authzEpUrl = new Property();
        authzEpUrl.setName(Constants.AuthenticatorConfig.OAUTH_AUTHORIZATION_ENDPOINT_URL);
        authzEpUrl.setDisplayName("Authorization Endpoint URL");
        authzEpUrl.setRequired(true);
        authzEpUrl.setDescription("The authorization endpoint URL of the external OpenID Connect provider. " +
                "(e.g., https://example.com/authorize)");
        authzEpUrl.setType("string");
        authzEpUrl.setDisplayOrder(++displayOrder);
        configProperties.add(authzEpUrl);

        final Property tokenEpUrl = new Property();
        tokenEpUrl.setName(Constants.AuthenticatorConfig.OAUTH_TOKEN_ENDPOINT_URL);
        tokenEpUrl.setDisplayName("Token Endpoint URL");
        tokenEpUrl.setRequired(true);
        tokenEpUrl.setDescription("The token endpoint URL of the external OpenID Connect provider. " +
                "(e.g., https://example.com/token)");
        tokenEpUrl.setType("string");
        tokenEpUrl.setDisplayOrder(++displayOrder);
        configProperties.add(tokenEpUrl);

        final Property callBackUrl = new Property();
        callBackUrl.setName(Constants.AuthenticatorConfig.CALLBACK_URL);
        callBackUrl.setDisplayName("Callback URL");
        callBackUrl.setRequired(true);
        callBackUrl.setDescription("The redirect URI registered at the external provider. " +
                "This will be used as the redirect_uri parameter sent in the authorization request.");
        callBackUrl.setType("string");
        callBackUrl.setDisplayOrder(++displayOrder);
        configProperties.add(callBackUrl);

        final Property jwksEndpointUrl = new Property();
        jwksEndpointUrl.setName(Constants.AuthenticatorConfig.JWKS_ENDPOINT_URL);
        jwksEndpointUrl.setDisplayName("JWKS Endpoint URL");
        jwksEndpointUrl.setRequired(true);
        jwksEndpointUrl.setDescription("The JWKS (JSON Web Key Set) endpoint of the external IdP. " +
                "This is used to fetch public keys for validating the ID Token signature.");
        jwksEndpointUrl.setType("string");
        jwksEndpointUrl.setDisplayOrder(++displayOrder);
        configProperties.add(jwksEndpointUrl);

        final Property userInfoUrl = new Property();
        userInfoUrl.setName(Constants.AuthenticatorConfig.USERINFO_URL);
        userInfoUrl.setDisplayName("UserInfo Endpoint URL");
        userInfoUrl.setRequired(true);
        userInfoUrl.setDescription("The UserInfo endpoint URL of the external IdP. " +
                "Additional user claims will be fetched from this endpoint.");
        userInfoUrl.setType("string");
        userInfoUrl.setDisplayOrder(++displayOrder);
        configProperties.add(userInfoUrl);

        // Group 2: Client Authentication
        final Property clientId = new Property();
        clientId.setName(Constants.AuthenticatorConfig.CLIENT_ID);
        clientId.setDisplayName("Client ID");
        clientId.setRequired(true);
        clientId.setDescription("The Client Identifier assigned by the external OpenID Connect provider.");
        clientId.setType("string");
        clientId.setDisplayOrder(++displayOrder);
        configProperties.add(clientId);

        final Property isPublicClient = new Property();
        isPublicClient.setName(Constants.AuthenticatorConfig.IS_PUBLIC_CLIENT);
        isPublicClient.setDisplayName("Public Client");
        isPublicClient.setRequired(true);
        isPublicClient.setDescription("Enable (set to 'true') if the client is public (e.g., a Single-Page App). " +
                "Public clients do not use a client secret for authentication. Defaults to 'false'.");
        isPublicClient.setType("boolean");
        isPublicClient.setValue("false");
        isPublicClient.setDisplayOrder(++displayOrder);
        configProperties.add(isPublicClient);

        final Property clientSecret = new Property();
        clientSecret.setName(Constants.AuthenticatorConfig.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setDescription("The Client Secret assigned by the external OIDC provider. Not required for public clients.");
        clientSecret.setType("string");
        clientSecret.setDisplayOrder(++displayOrder);
        clientSecret.setConfidential(true);
        configProperties.add(clientSecret);

        final Property clientAuth = new Property();
        clientAuth.setName(Constants.AuthenticatorConfig.SELECTED_CLIENT_AUTH);
        clientAuth.setDisplayName("Token Endpoint Authentication Method");
        clientAuth.setRequired(true);
        // Requires IdP Mgt JSP customisation to display the options in a dropdown and the default value (Property::setDefaultValue)
        // Therefore, we set the value itself (Property::setValue) and add the options to the description
        // clientAuth.setOptions(Constants.OIDC.OIDC_CLIENT_AUTH_METHODS);
        clientAuth.setValue(Constants.OIDC.CLIENT_SECRET_POST);
        clientAuth.setDescription("The method used to authenticate this client to the token endpoint. " +
                "Defaults to 'client_secret_post'. Allowed values: " + Arrays.toString(Constants.OIDC.CLIENT_AUTH_METHODS));
        clientAuth.setType("string");
        clientAuth.setDisplayOrder(++displayOrder);
        configProperties.add(clientAuth);

        // Group 3: JWT Assertion Configuration (for private_key_jwt)
        final Property jwtAssertionSignAlg = new Property();
        final String[] jwtAssertionSignAlgValuesSupported = authenticatorParams.getOrDefault(
                        Constants.AuthenticatorConfig.TOKEN_ENDPOINT_AUTH_SIGNING_ALG_VALUES_SUPPORTED, "RS256")
                .split(Constants.COMMA_SEPARATOR_REGEX);

        jwtAssertionSignAlg.setName(Constants.AuthenticatorConfig.JWT_ASSERTION_SIGN_ALG);
        jwtAssertionSignAlg.setDisplayName("Client Assertion Signing Algorithm");
        jwtAssertionSignAlg.setRequired(false);
        jwtAssertionSignAlg.setDescription("Algorithm to sign the client assertion JWT for private_key_jwt. " +
                "Must match the key-pair's algorithm family in the keystore. " +
                "Defaults to '" + jwtAssertionSignAlgValuesSupported[0] + "'. " +
                "Allowed options: " + Arrays.toString(jwtAssertionSignAlgValuesSupported));
        jwtAssertionSignAlg.setType("string");
        // Requires IdP Mgt JSP customisation to display the options in a dropdown and the default value (Property::setDefaultValue)
        // Therefore, we set the value itself (Property::setValue) and add the options to the description
        // jwtAssertionSignAlg.setOptions(jwtAssertionSignAlgValuesSupported); // From token_endpoint_auth_signing_alg_values_supported
        jwtAssertionSignAlg.setValue(jwtAssertionSignAlgValuesSupported[0]);
        jwtAssertionSignAlg.setDisplayOrder(++displayOrder);
        configProperties.add(jwtAssertionSignAlg);

        final Property audience = new Property();
        audience.setName(Constants.AuthenticatorConfig.JWT_AUDIENCE);
        audience.setDisplayName("Client Assertion Audience");
        audience.setRequired(false);
        audience.setDescription("The 'aud' (Audience) claim for the client assertion JWT. " +
                "If not set, the Token Endpoint URL will be used as the audience.");
        audience.setType("string");
        audience.setDisplayOrder(++displayOrder);
        configProperties.add(audience);

        final Property jwtExpiry = new Property();
        jwtExpiry.setName(Constants.AuthenticatorConfig.JWT_EXPIRY);
        jwtExpiry.setDisplayName("Client Assertion Lifetime (seconds)");
        jwtExpiry.setRequired(false);
        jwtExpiry.setDescription("The lifetime of the generated client assertion JWT in seconds. Defaults to 3600 seconds (1 hour).");
        jwtExpiry.setValue("3600");
        jwtExpiry.setType("string");
        jwtExpiry.setDisplayOrder(++displayOrder);
        configProperties.add(jwtExpiry);

        // Group 4: ID Token Processing
        final Property idTokenSignatureAlgorithm = new Property();
        final String[] idTokenSignatureAlgValuesSupported = authenticatorParams
                .getOrDefault(
                        Constants.AuthenticatorConfig.ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED, "RS256")
                .split(Constants.COMMA_SEPARATOR_REGEX);

        idTokenSignatureAlgorithm.setName(Constants.AuthenticatorConfig.ID_TOKEN_SIGN_ALG);
        idTokenSignatureAlgorithm.setDisplayName("ID Token Signature Algorithm");
        idTokenSignatureAlgorithm.setRequired(true);
        idTokenSignatureAlgorithm.setDescription("The algorithm the external IdP uses to sign the ID Token. " +
                "This must match one of the algorithms supported by the IdP. " +
                "Defaults to '" + idTokenSignatureAlgValuesSupported[0] + "'. " +
                "Allowed options: " + Arrays.toString(idTokenSignatureAlgValuesSupported));
        idTokenSignatureAlgorithm.setType("string");
        // Requires IdP Mgt JSP customisation to display the options in a dropdown and the default value (Property::setDefaultValue)
        // Therefore, we set the value itself (Property::setValue) and add the options to the description
        // idTokenSignatureAlgorithm.setOptions(idTokenSignatureAlgValuesSupported); // Based on id_token_signing_alg_values_supported
        idTokenSignatureAlgorithm.setValue(idTokenSignatureAlgValuesSupported[0]);
        idTokenSignatureAlgorithm.setDisplayOrder(++displayOrder);
        configProperties.add(idTokenSignatureAlgorithm);

        final Property isIdTokenEncrypted = new Property();
        isIdTokenEncrypted.setName(Constants.AuthenticatorConfig.IS_ID_TOKEN_ENCRYPTED);
        isIdTokenEncrypted.setDisplayName("ID Token is Encrypted");
        isIdTokenEncrypted.setRequired(true);
        isIdTokenEncrypted.setDescription("Enable if the ID Token from the external IdP is encrypted (JWE). " +
                "If enabled (set to 'true',) the ID Token will be decrypted using the specified encryption algorithm " +
                "and the client's signing public key.");
        isIdTokenEncrypted.setType("boolean");
        isIdTokenEncrypted.setValue("false");
        isIdTokenEncrypted.setDisplayOrder(++displayOrder);
        configProperties.add(isIdTokenEncrypted);

        final Property idTokenEncryptionAlg = new Property();
        final String[] idTokenEncryptionAlgValuesSupported = authenticatorParams
                .getOrDefault(
                        Constants.AuthenticatorConfig.ID_TOKEN_ENCRYPTION_ALG_VALUES_SUPPORTED, "RSA-OAEP-256")
                .split(Constants.COMMA_SEPARATOR_REGEX);

        idTokenEncryptionAlg.setName(Constants.AuthenticatorConfig.ID_TOKEN_ENC_ALG);
        idTokenEncryptionAlg.setDisplayName("ID Token Key Encryption Algorithm (alg)");
        idTokenEncryptionAlg.setRequired(false);
        idTokenEncryptionAlg.setDescription("The 'alg' used by the IdP to encrypt the ID Token. " +
                "Only required if 'ID Token is Encrypted' is enabled. " +
                "Defaults to '" + idTokenEncryptionAlgValuesSupported[0] + "'. " +
                "Allowed options: " + Arrays.toString(idTokenEncryptionAlgValuesSupported));
        idTokenEncryptionAlg.setType("string");
        idTokenEncryptionAlg.setValue(idTokenEncryptionAlgValuesSupported[0]);
        // Requires IdP Mgt JSP customisation to display the options in a dropdown and the default value (Property::setDefaultValue)
        // Therefore, we set the value itself (Property::setValue) and add the options to the description
        // idTokenEncryptionAlg.setOptions(idTokenEncryptionAlgValuesSupported); // From id_token_encryption_alg_values_supported
        idTokenEncryptionAlg.setDisplayOrder(++displayOrder);
        configProperties.add(idTokenEncryptionAlg);

        // Group 5: General Settings
        final Property userIdLocation = new Property();
        userIdLocation.setName(Constants.AuthenticatorConfig.IS_USERID_IN_CLAIMS);
        userIdLocation.setDisplayName("Use User ID from Claims");
        userIdLocation.setRequired(true);
        userIdLocation.setDescription("Enable to use a specific claim from the ID Token as the subject " +
                "identifier instead of the standard 'sub' claim. " +
                "The claim URI must be defined in the IdP's claim configuration. Defaults to 'false'.");
        userIdLocation.setType("boolean");
        userIdLocation.setValue("false");
        userIdLocation.setDisplayOrder(++displayOrder);
        configProperties.add(userIdLocation);

        final Property scopes = new Property();
        scopes.setName(Constants.AuthenticatorConfig.SCOPES);
        scopes.setDisplayName("Scopes");
        scopes.setRequired(false);
        scopes.setDescription("A space-separated list of scopes to request during authentication.");
        scopes.setValue(OIDCAuthenticatorConstants.OAUTH_OIDC_SCOPE);
        scopes.setType("string");
        scopes.setDisplayOrder(++displayOrder);
        configProperties.add(scopes);

        final Property additionalParams = new Property();
        additionalParams.setName(Constants.AuthenticatorConfig.ADDITIONAL_QUERY_STRING_PARAMETERS);
        additionalParams.setDisplayName("Additional Query Parameters");
        additionalParams.setRequired(false);
        additionalParams.setDescription("Additional parameters to include in the authentication request, " +
                "formatted as a URL query string (e.g., param1=value1&amp;param2=value2).");  // needs to be XML-encoded
        additionalParams.setType("string");
        additionalParams.setDisplayOrder(++displayOrder);
        configProperties.add(additionalParams);

        return configProperties;
    }
}
