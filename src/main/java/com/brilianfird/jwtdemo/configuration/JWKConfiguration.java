package com.brilianfird.jwtdemo.configuration;

import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.lang.JoseException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class JWKConfiguration {
  @Bean
  public PublicJsonWebKey es256PublicJsonWebKey()
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
