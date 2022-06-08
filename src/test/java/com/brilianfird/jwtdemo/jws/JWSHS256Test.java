package com.brilianfird.jwtdemo.jws;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.HmacKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

public class JWSHS256Test {
  @Test
  public void JWS_HS256() throws Exception {

    // generate  key
    byte[] key = new byte[32];
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(key);
    HmacKey hmacKey = new HmacKey(key);

    JwtClaims jwtClaims = new JwtClaims();
    jwtClaims.setSubject("7560755e-f45d-4ebb-a098-b8971c02ebef"); // set sub
    jwtClaims.setIssuedAtToNow(); // set iat
    jwtClaims.setExpirationTimeMinutesInTheFuture(10080); // set exp
    jwtClaims.setIssuer("https://codecurated.com"); // set iss
    jwtClaims.setStringClaim("name", "Brilian Firdaus"); // set name
    jwtClaims.setStringClaim("email", "brilianfird@gmail.com"); // set email
    jwtClaims.setClaim("email_verified", true); // set email_verified

    JsonWebSignature jws = new JsonWebSignature();
    // Set alg header as HMAC_SHA256
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
    // Set key to hmacKey
    jws.setKey(hmacKey);
    jws.setPayload(jwtClaims.toJson());

    String jwt = jws.getCompactSerialization(); // produce eyJ.. JWT

    // we don't need NO_CONSTRAINT and disable require signature anymore
    JwtConsumer jwtConsumer =
        new JwtConsumerBuilder()
            .setRequireIssuedAt()
            .setRequireExpirationTime()
            .setExpectedIssuer("https://codecurated.com")
            // set the verification key
            .setVerificationKey(hmacKey)
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
    Assertions.assertEquals(jws.getKey(), consumedJWS.getKey());
    Assertions.assertEquals(jwtClaims.toJson(), consumedJWTClaims.toJson());
  }
}
