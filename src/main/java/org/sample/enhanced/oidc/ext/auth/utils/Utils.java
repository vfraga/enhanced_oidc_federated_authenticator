package org.sample.enhanced.oidc.ext.auth.utils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sample.enhanced.oidc.ext.auth.internal.ServiceInstanceHolder;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCErrorConstants;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

public final class Utils {
    private static final Log log = LogFactory.getLog(Utils.class);


    private Utils() {
        // Prevent instantiation
    }

    public static String getClientIdConfig(final AuthenticationContext context) {
        return context.getAuthenticatorProperties().get(Constants.AuthenticatorConfig.CLIENT_ID);
    }

    public static String getClientSecretConfig(final AuthenticationContext context) {
        return context.getAuthenticatorProperties().get(Constants.AuthenticatorConfig.CLIENT_SECRET);
    }

    public static String getAuthorizationEndpointUrlConfig(final AuthenticationContext context) {
        return context.getAuthenticatorProperties().get(Constants.AuthenticatorConfig.OAUTH_AUTHORIZATION_ENDPOINT_URL);
    }

    public static String getTokenEndpointUrlConfig(final AuthenticationContext context) {
        return context.getAuthenticatorProperties().get(Constants.AuthenticatorConfig.OAUTH_TOKEN_ENDPOINT_URL);
    }

    public static String getCallbackUrlConfig(final AuthenticationContext context) {
        return context.getAuthenticatorProperties().get(Constants.AuthenticatorConfig.CALLBACK_URL);
    }

    public static String getUserInfoUrlConfig(final AuthenticationContext context) {
        return context.getAuthenticatorProperties().get(Constants.AuthenticatorConfig.USERINFO_URL);
    }

    public static boolean isPublicClientConfig(final AuthenticationContext context) {
        final String isPublicClient = context.getAuthenticatorProperties().get(Constants.AuthenticatorConfig.IS_PUBLIC_CLIENT);
        return Boolean.parseBoolean(isPublicClient);
    }

    public static boolean isIdTokenEncryptedConfig(final AuthenticationContext context) {
        final String isIdTokenEncrypted = context.getAuthenticatorProperties().get(Constants.AuthenticatorConfig.IS_ID_TOKEN_ENCRYPTED);
        return Boolean.parseBoolean(isIdTokenEncrypted);
    }

    public static String getJwksEndpointUrlConfig(final AuthenticationContext context) {
        return context.getAuthenticatorProperties().get(Constants.AuthenticatorConfig.JWKS_ENDPOINT_URL);
    }

    public static boolean isUserIdInClaimsConfig(final AuthenticationContext context) {
        final String isUserIdInClaims = context.getAuthenticatorProperties().get(Constants.AuthenticatorConfig.IS_USERID_IN_CLAIMS);
        return Boolean.parseBoolean(isUserIdInClaims);
    }

    public static String getAdditionalQueryStringParametersConfig(final AuthenticationContext context) {
        return context.getAuthenticatorProperties().get(Constants.AuthenticatorConfig.ADDITIONAL_QUERY_STRING_PARAMETERS);
    }

    public static String getSelectedClientAuthMethodConfig(final AuthenticationContext context) {
        return context.getAuthenticatorProperties().get(Constants.AuthenticatorConfig.SELECTED_CLIENT_AUTH);
    }

    public static String getAudienceConfig(final AuthenticationContext context) {
        final String audience = context.getAuthenticatorProperties().get(Constants.AuthenticatorConfig.JWT_AUDIENCE);
        return StringUtils.isBlank(audience) ? getTokenEndpointUrlConfig(context) : audience;
    }

    public static Long getJwtExpiryConfig(final AuthenticationContext context) {
        return Long.parseLong(context.getAuthenticatorProperties().get(Constants.AuthenticatorConfig.JWT_EXPIRY));
    }

    public static String getIdTokenEncAlgConfig(final AuthenticationContext context) {
        return context.getAuthenticatorProperties().get(Constants.AuthenticatorConfig.ID_TOKEN_ENC_ALG);
    }

    public static String getIdTokenSignAlgConfig(final AuthenticationContext context) {
        return context.getAuthenticatorProperties().get(Constants.AuthenticatorConfig.ID_TOKEN_SIGN_ALG);
    }

    public static String getJwtAssertionSignAlgConfig(final AuthenticationContext context) {
        return context.getAuthenticatorProperties().get(Constants.AuthenticatorConfig.JWT_ASSERTION_SIGN_ALG);
    }

    /**
     * Generates a key ID (kid) from the SHA-256 thumbprint of a certificate.
     * The thumbprint is Base64URL-encoded, which is the standard for JWTs.
     *
     * @param certificate The certificate to generate the thumbprint from.
     * @return A web-safe, standard kid string.
     */
    public static String getKeyID(final Certificate certificate) throws CertificateEncodingException, NoSuchAlgorithmException {
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");

        // Calculate the digest of the certificate's DER-encoded bytes
        final byte[] der = certificate.getEncoded();
        final byte[] thumbprintBytes = digest.digest(der);

        // Encode the thumbprint using the standard Base64URL encoder
        return Base64.getUrlEncoder().withoutPadding().encodeToString(thumbprintBytes);
    }

    /**
     * Creates a JWSSigner based on the given private key and JWS algorithm.
     * This method ensures that the key type is appropriate for the selected algorithm.
     *
     * @param privateKey The private key from the keystore.
     * @param algorithm  The JWS algorithm selected in the configuration.
     * @return A JWSSigner instance.
     * @throws AuthenticationFailedException If the key is incompatible with the algorithm.
     */
    public static JWSSigner createSigner(final PrivateKey privateKey, final JWSAlgorithm algorithm)
            throws AuthenticationFailedException {
        if (JWSAlgorithm.Family.RSA.contains(algorithm)) {
            if (privateKey instanceof RSAPrivateKey) {
                return new RSASSASigner(privateKey);
            }
            throw new AuthenticationFailedException("Key type is not RSA, but an RSA signing algorithm was selected.");
        } else if (JWSAlgorithm.Family.EC.contains(algorithm)) {
            if (privateKey instanceof ECPrivateKey) {
                try {
                    return new ECDSASigner((ECPrivateKey) privateKey);
                } catch (JOSEException e) {
                    throw new AuthenticationFailedException("Failed to create ECDSA signer.", e);
                }
            }
            throw new AuthenticationFailedException("Key type is not EC, but an ECDSA signing algorithm was selected.");
        } else {
            throw new AuthenticationFailedException("Unsupported JWS algorithm family for private_key_jwt: " + algorithm);
        }
        // Add support for other algorithm families here if needed (e.g., AESGCMKW, PBES2)
    }

    /**
     * Decrypts a JWE ID Token using the configured decryption key.
     *
     * @param jweString The serialized JWE string.
     * @param context   The Authentication Context, used to get configuration.
     * @return The serialized, signed JWT (JWS) string from inside the JWE.
     * @throws AuthenticationFailedException if decryption fails.
     */
    public static String decryptIdToken(final String jweString,
                                        final AuthenticationContext context,
                                        final AuthenticatorConfig authenticatorConfig)
            throws AuthenticationFailedException {
        try {
            final JWEObject jweObject = JWEObject.parse(jweString);

            final JWEAlgorithm algorithm = jweObject.getHeader().getAlgorithm();

            final String expectedAlg = getIdTokenEncAlgConfig(context);
            if (StringUtils.isNotBlank(expectedAlg) && !expectedAlg.equals(algorithm.getName())) {
                throw new AuthenticationFailedException("JWE algorithm mismatch. Expected " + expectedAlg + " but received " + algorithm.getName());
            }

            final KeyPairStore keyPairStore = new KeyPairStore(authenticatorConfig.getParameterMap());

            final PrivateKey decryptionKey = keyPairStore.getSigningPrivateKey();
            final JWEDecrypter decrypter = createDecrypter(decryptionKey, algorithm);

            jweObject.decrypt(decrypter);

            final SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
            if (signedJWT == null) {
                throw new AuthenticationFailedException("Payload of the JWE is not a valid Signed JWT.");
            }

            log.debug("Successfully decrypted JWE with algorithm: " + algorithm.getName());
            return signedJWT.serialize();
        } catch (ParseException | JOSEException e) {
            throw new AuthenticationFailedException("Failed to decrypt the ID Token.", e);
        }
    }

    /**
     * Creates a JWEDecrypter based on the JWE algorithm and the configured private key.
     *
     * @param privateKey The decryption private key.
     * @param algorithm  The key encryption algorithm from the JWE header.
     * @return A JWEDecrypter instance.
     * @throws AuthenticationFailedException If the key is incompatible or the algorithm is unsupported.
     */
    public static JWEDecrypter createDecrypter(final PrivateKey privateKey, final JWEAlgorithm algorithm)
            throws AuthenticationFailedException {

        if (JWEAlgorithm.Family.RSA.contains(algorithm)) {
            if (privateKey instanceof RSAPrivateKey) {
                return new RSADecrypter(privateKey);
            }
            throw new AuthenticationFailedException("Key type is not RSA, but an RSA key encryption algorithm was used.");

        } else if (JWEAlgorithm.Family.ECDH_ES.contains(algorithm)) {
            if (privateKey instanceof ECPrivateKey) {
                try {
                    return new ECDHDecrypter((ECPrivateKey) privateKey);
                } catch (JOSEException e) {
                    throw new AuthenticationFailedException("Failed to create ECDH decrypter.", e);
                }
            }
            throw new AuthenticationFailedException("Key type is not EC, but an ECDH-ES key encryption algorithm was used.");
        }

        // Add support for other algorithm families here if needed (e.g., AESGCMKW, PBES2)
        throw new AuthenticationFailedException("Unsupported JWE key encryption algorithm: " + algorithm.getName());
    }

    /**
     * Validates the signature and claims of a JWS ID Token.
     *
     * @param idTokenString The serialized JWS string.
     * @param context       The Authentication Context.
     * @return The validated JWTClaimsSet.
     * @throws AuthenticationFailedException if validation fails.
     */
    public static JWTClaimsSet validateIdToken(final String idTokenString, final AuthenticationContext context)
            throws AuthenticationFailedException {
        try {
            final ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

            final String issuer = SignedJWT.parse(idTokenString).getJWTClaimsSet().getIssuer();
            final URL jwksURI = new URL(Utils.getJwksEndpointUrlConfig(context));
            final JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(jwksURI);

            final JWSAlgorithm expectedJwsAlg = JWSAlgorithm.parse(Utils.getIdTokenSignAlgConfig(context));
            final JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(expectedJwsAlg, keySource);

            jwtProcessor.setJWSKeySelector(keySelector);

            final JWTClaimsSet claimsSet = jwtProcessor.process(idTokenString, null);

            final String clientId = getClientIdConfig(context);
            if (!claimsSet.getAudience().contains(clientId)) {
                throw new AuthenticationFailedException("ID Token audience claim does not contain client id.");
            }
            if (!claimsSet.getIssuer().equals(issuer)) {
                throw new AuthenticationFailedException("ID Token issuer claim validation failed.");
            }

            if (log.isDebugEnabled()) {
                log.debug("ID Token signature and claims validated successfully.");
            }

            return claimsSet;

        } catch (ParseException | BadJOSEException | MalformedURLException | JOSEException e) {
            throw new AuthenticationFailedException("ID Token validation failed.", e);
        }
    }

    // Method copied from WSO2's source code to retrieve the multi attribute separator, as it's private in the original codebase.
    public static String getMultiAttributeSeparator(final AuthenticationContext context, final String authenticatedUserId)
            throws AuthenticationFailedException {

        try {
            final String tenantDomain;

            if (StringUtils.isBlank(context.getTenantDomain())) {
                tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            } else {
                tenantDomain = context.getTenantDomain();
            }

            final int tenantId = ServiceInstanceHolder.getInstance().getRealmService().getTenantManager().getTenantId(tenantDomain);
            final UserRealm userRealm = ServiceInstanceHolder.getInstance().getRealmService().getTenantUserRealm(tenantId);

            if (userRealm != null) {
                final UserStoreManager userStore = (UserStoreManager) userRealm.getUserStoreManager();
                final String attributeSeparator = userStore.getRealmConfiguration()
                        .getUserStoreProperty(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);

                if (log.isDebugEnabled()) {
                    log.debug("For the authenticated user: " + authenticatedUserId + "@" + tenantDomain + ", " +
                            "the multi attribute separator is: " + attributeSeparator);
                }
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException(
                    OIDCErrorConstants.ErrorMessages.RETRIEVING_MULTI_ATTRIBUTE_SEPARATOR_FAILED.getCode(),
                    OIDCErrorConstants.ErrorMessages.RETRIEVING_MULTI_ATTRIBUTE_SEPARATOR_FAILED.getMessage(),
                    AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId),
                    e
            );
        }
        return null;
    }

    /**
     * Helper method to construct the client assertion JWT.
     */
    public static String buildClientAssertion(final AuthenticationContext context,
                                       final JWSSigner signer,
                                       final JWSAlgorithm algorithm,
                                       final String keyId) throws JOSEException {

        final String clientId = getClientIdConfig(context);
        final String audience = getAudienceConfig(context);
        final long expiry = getJwtExpiryConfig(context);

        // Build JWT Claims
        final Instant now = Instant.now();
        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(clientId)
                .subject(clientId)
                .audience(audience)
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(expiry)))
                .build();

        // Build JWS Header
        final JWSHeader.Builder headerBuilder = new JWSHeader.Builder(algorithm);
        if (StringUtils.isNotBlank(keyId)) {
            headerBuilder.keyID(keyId);
        }

        // Sign and Serialize
        final SignedJWT signedJWT = new SignedJWT(headerBuilder.build(), claimsSet);
        signedJWT.sign(signer);

        final String serializedJwt = signedJWT.serialize();
        if (log.isDebugEnabled()) {
            log.debug("Generated client assertion JWT: " + serializedJwt);
        }
        return serializedJwt;
    }
}
