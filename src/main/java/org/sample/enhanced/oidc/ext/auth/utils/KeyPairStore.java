package org.sample.enhanced.oidc.ext.auth.utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Map;
import java.util.Objects;

public class KeyPairStore {

    private final Map<String, String> authenticatorConfigs;

    public KeyPairStore(final Map<String, String> authenticatorConfigs) {
        this.authenticatorConfigs = Objects.requireNonNull(authenticatorConfigs, "Authenticator configurations cannot be null.");
        if (authenticatorConfigs.isEmpty()) {
            throw new IllegalArgumentException("Authenticator configurations cannot be empty.");
        }
    }

    public PrivateKey getSigningPrivateKey() {
        return (PrivateKey) getKey(getSigningKeyStore(), authenticatorConfigs.get(Constants.AuthenticatorConfig.SIGNING_KEY_ALIAS), authenticatorConfigs.get(Constants.AuthenticatorConfig.SIGNING_KEY_PASSWORD));
    }

    public PublicKey getSigningPublicKey() {
        return getPublicKey(getSigningKeyStore(), authenticatorConfigs.get(Constants.AuthenticatorConfig.SIGNING_KEY_ALIAS));
    }

    public Certificate getSigningCertificate() {
        return getCertificate(getSigningKeyStore(), authenticatorConfigs.get(Constants.AuthenticatorConfig.SIGNING_KEY_ALIAS));
    }

    private Key getKey(final KeyStore keyStore, final String alias, final String password) {
        try {
            final Key key = keyStore.getKey(alias, password.toCharArray());
            if (key == null) {
                throw new RuntimeException("Key not found for alias: " + alias);
            }
            return key;
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new RuntimeException("Error retrieving key for alias: " + alias, e);
        }
    }

    private PublicKey getPublicKey(final KeyStore keyStore, final String alias) {
        return getCertificate(keyStore, alias).getPublicKey();
    }

    private Certificate getCertificate(final KeyStore keyStore, final String alias) {
        try {
            final Certificate certificate = keyStore.getCertificate(alias);
            if (certificate == null) {
                throw new RuntimeException("Certificate not found for alias: " + alias);
            }
            return certificate;
        } catch (KeyStoreException e) {
            throw new RuntimeException("Error retrieving certificate for alias: " + alias, e);
        }
    }

    public KeyStore getSigningKeyStore() {
        final String signingKeystorePath = authenticatorConfigs.get(Constants.AuthenticatorConfig.SIGNING_KEYSTORE_PATH);
        final String signingKeystorePassword = authenticatorConfigs.get(Constants.AuthenticatorConfig.SIGNING_KEYSTORE_PASSWORD);
        final String signingKeystoreType = authenticatorConfigs.get(Constants.AuthenticatorConfig.SIGNING_KEYSTORE_TYPE);

        if (signingKeystorePath == null || signingKeystorePassword == null || signingKeystoreType == null) {
            throw new IllegalArgumentException("Signing keystore configuration is incomplete.");
        }

        try {
            final KeyStore keyStore = KeyStore.getInstance(signingKeystoreType);
            try (final FileInputStream stream = new FileInputStream(signingKeystorePath)) {
                keyStore.load(stream, signingKeystorePassword.toCharArray());
                return keyStore;
            }
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }
}