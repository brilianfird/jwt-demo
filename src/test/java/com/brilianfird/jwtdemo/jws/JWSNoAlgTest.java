package com.brilianfird.jwtdemo.jws;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.junit.jupiter.api.Test;

public class JWSNoAlgTest {
  @Test
  public void JWS_noAlg() throws Exception {

    JwtClaims jwtClaims = new JwtClaims();
    jwtClaims.setSubject("7560755e-f45d-4ebb-a098-b8971c02ebef");
    jwtClaims.setIssuedAtToNow();
    jwtClaims.setExpirationTimeMinutesInTheFuture(Integer.MAX_VALUE);
    jwtClaims.setIssuer("https://codecurated.com");
    jwtClaims.setStringClaim("name", "Brilian Firdaus");
    jwtClaims.setStringClaim("email", "brilianfird@gmail.com");
    jwtClaims.setClaim("email_verified", true);

    JsonWebSignature jws = new JsonWebSignature();

    jws.setPayload(jwtClaims.toJson());
    jws.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.NONE);

    String jwt = jws.getCompactSerialization();
    System.out.println("JWT: " + jwt);
  }

  @Test
  public void JWS_consume() throws Exception {
    String jwt =
        "eyJhbGciOiJub25lIn0.eyJzdWIiOiI3NTYwNzU1ZS1mNDVkLTRlYmItYTA5OC1iODk3MWMwMmViZWYiLCJpYXQiOjE2NTQ3MDIxMTI"
            + "sImV4cCI6MTMwNTAzNzIwOTkyLCJpc3MiOiJodHRwczovL2NvZGVjdXJhdGVkLmNvbSIsIm5hbWUiOiJCcmlsaWFuIEZpcmR"
            + "hdXMiLCJlbWFpbCI6ImJyaWxpYW5maXJkQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlfQ.";

    JwtConsumer jwtConsumer =
        new JwtConsumerBuilder()
            .setJwsAlgorithmConstraints(
                AlgorithmConstraints.NO_CONSTRAINTS) // required for NONE alg
            .setDisableRequireSignature() // disable signature requirement
            .setRequireIssuedAt() // require the JWT to have iat field
            .setRequireExpirationTime() // require the JWT to have exp field
            .setExpectedIssuer(
                "https://codecurated.com") // expect the iss to be https://codecurated.com
            .build();

    JwtContext jwtContext = jwtConsumer.process(jwt); // process JWT to jwt context

    JsonWebSignature jws = (JsonWebSignature) jwtContext.getJoseObjects().get(0); // get the JWS
    JwtClaims jwtClaims = jwtContext.getJwtClaims(); // get claims

    System.out.println(jwtClaims.getClaimsMap()); // print claims as map
  }
}
