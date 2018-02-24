package com.aberkes.controllers;

import java.util.Base64;
import com.aberkes.models.Keys;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;

@RestController
@RequestMapping("/api/signing")
public class SigningController
{
    @GetMapping("/generate")
    public ResponseEntity<Keys> generate()
    {
        byte[] encodedPublicKey;
        byte[] encodedPrivateKey;

        try
        {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

            KeyPair kp = generator.generateKeyPair();

            encodedPublicKey = kp.getPublic().getEncoded();
            encodedPrivateKey = kp.getPrivate().getEncoded();
        }
        catch (NoSuchAlgorithmException e)
        {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }


        Keys keys = new Keys();
        keys.setPublicKey(Base64.getEncoder().encodeToString(encodedPublicKey));
        keys.setPrivateKey(Base64.getEncoder().encodeToString(encodedPrivateKey));

        return ResponseEntity.ok(keys);
    }

    @PostMapping("/sign")
    public ResponseEntity signJwt(@RequestBody String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        Calendar c = Calendar.getInstance();
        c.add(Calendar.YEAR, 1);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

        Algorithm algorithm = Algorithm.RSA256(null, rsaPrivateKey);
        return ResponseEntity.ok(JWT.create()
                .withAudience("audience")
                .withIssuer("Demo Issuer")
                .withIssuedAt(new Date())
                .withExpiresAt(c.getTime())
                .sign(algorithm)
                .toString());
    }
}
