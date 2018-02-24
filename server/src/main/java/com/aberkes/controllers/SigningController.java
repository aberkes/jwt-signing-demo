package com.aberkes.controllers;

import java.util.Base64;
import com.aberkes.models.Keys;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@RestController
@RequestMapping("/api/signing")
public class SigningController
{
    @GetMapping("/generate")
    public ResponseEntity<Keys> generate()
    {
        RSAPublicKey publicKey;
        RSAPrivateKey privateKey;

        try
        {
            KeyPairGenerator generator = null;
            generator = KeyPairGenerator.getInstance("RSA");

            KeyPair kp = generator.generateKeyPair();

            byte[] encodedPublicKey = kp.getPublic().getEncoded();
            byte[] encodedPrivateKey = kp.getPrivate().getEncoded();

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);

            publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
            privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
        }
        catch (NoSuchAlgorithmException e)
        {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
        catch (InvalidKeySpecException e)
        {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }


        Keys keys = new Keys()
        {{
            setPublicKey(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
            setPrivateKey(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        }};

        return ResponseEntity.ok(keys);
    }

    @PostMapping("/sign")
    public ResponseEntity signJwt(String privateKey)
    {
        return ResponseEntity.badRequest().build();
    }
}
