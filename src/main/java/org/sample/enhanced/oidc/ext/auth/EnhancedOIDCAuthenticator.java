package org.sample.enhanced.oidc.ext.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.sample.enhanced.oidc.ext.auth.utils.Constants;
import org.sample.enhanced.oidc.ext.auth.utils.KeyPairStore;
import org.sample.enhanced.oidc.ext.auth.utils.Utils;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCErrorConstants;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.base.IdentityConstants.FEDERATED_IDP_SESSION_ID;

public class EnhancedOIDCAuthenticator extends OpenIDConnectAuthenticator {
    private static final Log log = LogFactory.getLog(EnhancedOIDCAuthenticator.class);

    private static final List<String> NON_USER_ATTRIBUTES = Arrays.asList(
            "iss", "aud", "exp", "iat", "at_hash", "acr", "amr", "azp", "nbf"
    );

    @Override
    protected OAuthClientRequest getAccessTokenRequest(final AuthenticationContext context,
                                                       final OAuthAuthzResponse authzResponse)
            throws AuthenticationFailedException {

        final String clientId = Utils.getClientIdConfig(context);
        final String tokenEndpoint = Utils.getTokenEndpointUrlConfig(context);
        final String callbackUrl = Utils.getCallbackUrlConfig(context);
        final String selectedAuthMethod = Utils.getSelectedClientAuthMethodConfig(context);

        log.info(String.format("Building token request for client '%s' using authentication method: '%s'", clientId, selectedAuthMethod));

        try {
            OAuthClientRequest.TokenRequestBuilder tokenRequestBuilder = OAuthClientRequest.tokenLocation(tokenEndpoint)
                    .setGrantType(GrantType.AUTHORIZATION_CODE)
                    .setCode(authzResponse.getCode())
                    .setRedirectURI(callbackUrl);

            if (Utils.isPublicClientConfig(context)) {
                if (log.isDebugEnabled()) {
                    log.debug("No client authentication will be included in the request as IdP is configured as public client.");
                }
                // For public clients, we do not include client authentication in the request, only the client_id
                tokenRequestBuilder.setClientId(clientId);
                return tokenRequestBuilder.buildBodyMessage();
            }

            switch (selectedAuthMethod) {
                case Constants.OIDC.CLIENT_SECRET_BASIC:
                    if (log.isDebugEnabled()) {
                        log.debug("Using client_secret_basic for client authentication.");
                    }
                    final String clientSecret = Utils.getClientSecretConfig(context);
                    final String basicAuthHeader = "Basic " + Base64.encodeBase64String((clientId + ":" + clientSecret).getBytes());
                    tokenRequestBuilder.buildBodyMessage().addHeader(OAuth.HeaderType.AUTHORIZATION, basicAuthHeader);
                    break;

                case Constants.OIDC.CLIENT_SECRET_POST:
                    if (log.isDebugEnabled()) {
                        log.debug("Using client_secret_post for client authentication.");
                    }
                    tokenRequestBuilder.setClientId(clientId);
                    tokenRequestBuilder.setClientSecret(Utils.getClientSecretConfig(context));
                    break;

                case Constants.OIDC.CLIENT_SECRET_JWT:
                    if (log.isDebugEnabled()) {
                        log.debug("Using client_secret_jwt for client authentication.");
                    }
                    final String secret = Utils.getClientSecretConfig(context);
                    final String clientSecretJwt = Utils.buildClientAssertion(context, new MACSigner(secret), JWSAlgorithm.HS256, null);

                    tokenRequestBuilder.setClientId(clientId);
                    tokenRequestBuilder.setParameter(Constants.OIDC.CLIENT_ASSERTION_TYPE, Constants.OIDC.JWT_BEARER_GRANT_TYPE);
                    tokenRequestBuilder.setParameter(Constants.OIDC.CLIENT_ASSERTION, clientSecretJwt);
                    break;

                case Constants.OIDC.PRIVATE_KEY_JWT:
                    if (log.isDebugEnabled()) {
                        log.debug("Using private_key_jwt for client authentication.");
                    }

                    final String jwtAssertionSignAlgStr = Utils.getJwtAssertionSignAlgConfig(context);
                    if (StringUtils.isBlank(jwtAssertionSignAlgStr)) {
                        throw new AuthenticationFailedException("JWT Assertion Signing Algorithm is not configured.");
                    }
                    final JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(jwtAssertionSignAlgStr);

                    final KeyPairStore keyPairStore = new KeyPairStore(getAuthenticatorConfig().getParameterMap());

                    final PrivateKey signingKey = keyPairStore.getSigningPrivateKey();
                    final Certificate certificate = keyPairStore.getSigningCertificate();
                    final String kid = Utils.getKeyID(certificate);

                    final JWSSigner signer = Utils.createSigner(signingKey, jwsAlgorithm);

                    final String privateKeyJwt = Utils.buildClientAssertion(context, signer, jwsAlgorithm, kid);

                    tokenRequestBuilder.setClientId(clientId);
                    tokenRequestBuilder.setParameter(Constants.OIDC.CLIENT_ASSERTION_TYPE, Constants.OIDC.JWT_BEARER_GRANT_TYPE);
                    tokenRequestBuilder.setParameter(Constants.OIDC.CLIENT_ASSERTION, privateKeyJwt);
                    break;

                default:
                    throw new AuthenticationFailedException("Unsupported client authentication method: " + selectedAuthMethod);
            }

            return tokenRequestBuilder.buildBodyMessage();

        } catch (OAuthSystemException | JOSEException | CertificateEncodingException | NoSuchAlgorithmException e) {
            throw new AuthenticationFailedException("Error building access token request for method " + selectedAuthMethod, e);
        }
    }

    @Override
    public void processAuthenticationResponse(final HttpServletRequest request, final HttpServletResponse response,
                                              final AuthenticationContext context) throws AuthenticationFailedException {
        try {
            // Standard
            final OAuthAuthzResponse authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            final OAuthClientRequest accessTokenRequest = getAccessTokenRequest(context, authzResponse);
            final OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            final OAuthClientResponse oAuthResponse = oAuthClient.accessToken(accessTokenRequest);

            String idTokenString = oAuthResponse.getParam(OIDCAuthenticatorConstants.ID_TOKEN);

            if (StringUtils.isBlank(idTokenString) && requiredIDToken(context.getAuthenticatorProperties())) {
                throw new AuthenticationFailedException("ID Token not found in the token response.");
            }

            // Custom code block
            if (StringUtils.countMatches(idTokenString, ".") == 4 && Utils.isIdTokenEncryptedConfig(context)) {
                log.debug("ID Token appears to be a JWE. Attempting decryption.");
                idTokenString = Utils.decryptIdToken(idTokenString, context, getAuthenticatorConfig());
            }

            final JWTClaimsSet claimsSet = Utils.validateIdToken(idTokenString, context);

            // Superclass code below
            context.setProperty(OIDCAuthenticatorConstants.ACCESS_TOKEN, oAuthResponse.getParam(OAuth.OAUTH_ACCESS_TOKEN));

            final Map<String, Object> jwtClaims = claimsSet.getClaims();

            // Handle session management for Single Logout (SLO)
            final String idpName = context.getExternalIdP().getIdPName();
            final String sidClaim = (String) jwtClaims.get(OIDCAuthenticatorConstants.Claim.SID);

            if (StringUtils.isNotBlank(sidClaim) && StringUtils.isNotBlank(idpName)) {
                context.setProperty(FEDERATED_IDP_SESSION_ID + idpName, sidClaim);
            }

            // Determine the unique subject identifier for the user
            final String authenticatedUserId = getAuthenticatedUserId(context, oAuthResponse, jwtClaims);

            // Build the claim mappings for user attributes filtering out non-user attributes
            final String attributeSeparator = Utils.getMultiAttributeSeparator(context, authenticatedUserId);
            final Map<ClaimMapping, String> claims = new HashMap<>();

            jwtClaims.entrySet().stream()
                    .filter(entry -> !NON_USER_ATTRIBUTES.contains(entry.getKey()))
                    .forEach(entry -> buildClaimMappings(claims, entry, attributeSeparator));

            // Fetch additional attributes from the UserInfo endpoint.
            claims.putAll(getSubjectAttributes(oAuthResponse, context.getAuthenticatorProperties()));

            final AuthenticatedUser authenticatedUser = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId);
            authenticatedUser.setFederatedIdPName(idpName);
            authenticatedUser.setUserAttributes(claims);

            // Set the fully formed user object into the context
            context.setSubject(authenticatedUser);

            if (log.isDebugEnabled()) {
                log.debug("Authentication successful. Authenticated user: " + context.getSubject().getAuthenticatedSubjectIdentifier());
            }

        } catch (final OAuthProblemException | OAuthSystemException e) {
            log.error(e.getMessage(), e);
            throw new AuthenticationFailedException("OAuth error while processing OIDC authentication response.", e);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new AuthenticationFailedException("Unexpected error while processing OIDC authentication response.", e);
        }
    }

    // Method from WSO2's source code as it's private in the superclass
    private String getAuthenticatedUserId(final AuthenticationContext context, final OAuthClientResponse oAuthResponse,
                                          final Map<String, Object> idTokenClaims) throws AuthenticationFailedException {

        String authenticatedUserId;
        if (Utils.isUserIdInClaimsConfig(context)) {
            authenticatedUserId = getSubjectFromUserIDClaimURI(context, idTokenClaims);
            if (StringUtils.isNotBlank(authenticatedUserId)) {
                if (log.isDebugEnabled()) {
                    log.debug("Authenticated user id: " + authenticatedUserId + " was found among id_token claims.");
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Subject claim could not be found amongst id_token claims. Defaulting to the 'sub' " +
                            "attribute in id_token as authenticated user id.");
                }
                // Default to userId sent as the 'sub' claim.
                authenticatedUserId = getAuthenticateUser(context, idTokenClaims, oAuthResponse);
            }
        } else {
            authenticatedUserId = getAuthenticateUser(context, idTokenClaims, oAuthResponse);
            if (log.isDebugEnabled()) {
                log.debug("Authenticated user id: " + authenticatedUserId + " retrieved from the 'sub' claim.");
            }
        }

        if (StringUtils.isBlank(authenticatedUserId)) {
            throw new AuthenticationFailedException(
                    OIDCErrorConstants.ErrorMessages.USER_ID_NOT_FOUND_IN_ID_TOKEN_SENT_BY_FEDERATED_IDP.getCode(),
                    OIDCErrorConstants.ErrorMessages.USER_ID_NOT_FOUND_IN_ID_TOKEN_SENT_BY_FEDERATED_IDP.getMessage()
            );
        }
        return authenticatedUserId;
    }

    @Override
    public List<Property> getConfigurationProperties() {
        return AuthenticatorSettings.getConfigurationProperties(getAuthenticatorConfig().getParameterMap());
    }

    @Override
    public String getFriendlyName() {
        return Constants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return Constants.AUTHENTICATOR_NAME;
    }
}
