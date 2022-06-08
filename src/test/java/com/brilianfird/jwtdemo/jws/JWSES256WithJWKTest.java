package com.brilianfird.jwtdemo.jws;

import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class JWSES256WithJWKTest {

  // Make sure to run the application before running this test
  @Test
  public void JWS_ES256_JWK() throws Exception {
    // generate  key
    PublicJsonWebKey ellipticCurveJsonWebKey = initiateES256JWK();

    JsonWebKeySet jsonWebKeySet = new JsonWebKeySet();
    jsonWebKeySet.addJsonWebKey(ellipticCurveJsonWebKey);

    JwtClaims jwtClaims = new JwtClaims();
    jwtClaims.setSubject("7560755e-f45d-4ebb-a098-b8971c02ebef"); // set sub
    jwtClaims.setIssuedAtToNow(); // set iat
    jwtClaims.setExpirationTimeMinutesInTheFuture(10080); // set exp
    jwtClaims.setIssuer("https://codecurated.com"); // set iss
    jwtClaims.setStringClaim("name", "Brilian Firdaus"); // set name
    jwtClaims.setStringClaim("email", "brilianfird@gmail.com"); // set email
    jwtClaims.setClaim("email_verified", true); // set email_verified

    JsonWebSignature jws = new JsonWebSignature();
    // Set alg header as ECDSA_USING_P256_CURVE_AND_SHA256
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
    // Set key to the generated private key
    jws.setKey(ellipticCurveJsonWebKey.getPrivateKey());
    jws.setPayload(jwtClaims.toJson());

    String jwt = jws.getCompactSerialization(); // produce eyJ.. JWT

    // we don't need NO_CONSTRAINT and disable require signature anymore
    HttpsJwks httpsJkws = new HttpsJwks("http://localhost:8080/jwk");
    HttpsJwksVerificationKeyResolver verificationKeyResolver =
        new HttpsJwksVerificationKeyResolver(httpsJkws);

    JwtConsumer jwtConsumer =
        new JwtConsumerBuilder()
            .setRequireIssuedAt()
            .setRequireExpirationTime()
            .setExpectedIssuer("https://codecurated.com")
            // set the verification key as the public key
            .setVerificationKeyResolver(verificationKeyResolver)
            .build();

    // process JWT to jwt context
    JwtContext jwtContext = jwtConsumer.process(jwt);
    // get JWS object
    JsonWebSignature consumedJWS = (JsonWebSignature) jwtContext.getJoseObjects().get(0);
    // get claims
    JwtClaims consumedJWTClaims = jwtContext.getJwtClaims();

    // print claims as map
    System.out.println(consumedJWTClaims.getClaimsMap());

    // Assert header, key, and claims
    Assertions.assertEquals(jws.getAlgorithmHeaderValue(), consumedJWS.getAlgorithmHeaderValue());

    // The key won't be equal because it's asymmetric
    Assertions.assertNotEquals(jws.getKey(), consumedJWS.getKey());
    Assertions.assertEquals(jwtClaims.toJson(), consumedJWTClaims.toJson());
  }

  public PublicJsonWebKey initiateES256JWK()
      throws NoSuchAlgorithmException, JoseException, InvalidKeySpecException {
    PKCS8EncodedKeySpec formatted_private =
        new PKCS8EncodedKeySpec(
            Base64.getDecoder()
                .decode(
                    "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBW+TML/g3QbmRbnFTaDNyHuAvmQ9XgcO8ci/I42Y+mlQ=="));
    X509EncodedKeySpec formatted_public =
        new X509EncodedKeySpec(
            Base64.getDecoder()
                .decode(
                    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEadEbLi2ruhj1YYBYw5iuekpzrFk563Q4TsFdAxhAKoATI9/o99P7MUQpbQ1TL/6VBRj3xnpnKVpkiElyI7yotw=="));

    KeyFactory keyFactory = KeyFactory.getInstance("EC");
    PublicKey publicKey = keyFactory.generatePublic(formatted_public);
    PrivateKey privateKey = keyFactory.generatePrivate(formatted_private);

    PublicJsonWebKey publicJsonWebKey = PublicJsonWebKey.Factory.newPublicJwk(publicKey);
    publicJsonWebKey.setPrivateKey(privateKey);
    publicJsonWebKey.setKeyId("2022-05-08");
    return publicJsonWebKey;
  }
}
