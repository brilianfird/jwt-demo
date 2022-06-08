# JWT Demo

A simple application containing JWT tests using `jose4j` library.

The application can also be run to host JWK endpoint in `/jwk` for JWE with JWK test.

## Tech Stack

- Java 11
- Spring boot 2.6.7

## How to Run

The application is packaged with maven, to run you need to install Java 11 and Maven.

Use the following command to run the application:

`mvn spring-boot:run`

## JWS

- [JWS without signing algorithm](src/test/java/com/brilianfird/jwtdemo/jws/JWSNoAlgTest.java)
- [JWS HS256](src/test/java/com/brilianfird/jwtdemo/jws/JWSHS256Test.java)
- [JWS ES256](src/test/java/com/brilianfird/jwtdemo/jws/JWSES256Test.java)
- [JWS ES256 with hosted JWK](src/test/java/com/brilianfird/jwtdemo/jws/JWSES256WithJWKTest.java)

## JWE

- [JWE ECDHES](src/test/java/com/brilianfird/jwtdemo/jwe/JWE_ECDHESTest.java)



