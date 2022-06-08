package com.brilianfird.jwtdemo.jwe;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;

public class JWE_ECDHESTest {
  @Test
  public void JWE_ECDHES() throws Exception {
    // Determine signature algorithm and encryption algorithm
    String alg = KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW;
    String encryptionAlgorithm = ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256;

    // Generate EC JWK
    EllipticCurveJsonWebKey ecJWK = EcJwkGenerator.generateJwk(EllipticCurves.P256);

    // Create
    JwtClaims jwtClaims = new JwtClaims();
    jwtClaims.setIssuer("https://codecurated.com");
    jwtClaims.setExpirationTimeMinutesInTheFuture(300);
    jwtClaims.setIssuedAtToNow();
    jwtClaims.setSubject("12345");

    // Create JWE
    JsonWebEncryption jwe = new JsonWebEncryption();
    jwe.setPlaintext(jwtClaims.toJson());

    // Set JWE's signature algorithm and encryption algorithm
    jwe.setAlgorithmHeaderValue(alg);
    jwe.setEncryptionMethodHeaderParameter(encryptionAlgorithm);

    // Unlike JWS, to create the JWE we use the public key
    jwe.setKey(ecJWK.getPublicKey());
    String compactSerialization = jwe.getCompactSerialization();
    System.out.println(compactSerialization);

    // Create JWT Consumer
    JwtConsumer jwtConsumer =
        new JwtConsumerBuilder()
            // We set the private key as decryption key
            .setDecryptionKey(ecJWK.getPrivateKey())
            // JWE doesn't have signature, so we disable it
            .setDisableRequireSignature()
            .build();

    // Get the JwtContext of the JWE
    JwtContext jwtContext = jwtConsumer.process(compactSerialization);

    System.out.println(jwtContext.getJwtClaims());
  }
}
