package com.example.myapplication2;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;

import android.security.keystore.KeyInfo;
import android.text.method.ScrollingMovementMethod;
import android.util.Base64;
import android.widget.TextView;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;



public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        TextView textBox = findViewById(R.id.textView1);

        KeyPairGenerator keyPairGenerator = null;

        try {
            keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder("key1", KeyProperties.PURPOSE_SIGN)
                            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                            .setDigests(KeyProperties.DIGEST_SHA256,
                                    KeyProperties.DIGEST_SHA384,
                                    KeyProperties.DIGEST_SHA512)
                            // Only permit the private key to be used if the user
                            // authenticated within the last five minutes.
                            .setUserAuthenticationRequired(true) //Richiede la presenza di una protezione del dispositivo (in caso di assenza di protezione lancia una eccezione)
                            .setUserAuthenticationValidityDurationSeconds(5 * 60)
                            // Request an attestation with challenge "hello world".
                            .setAttestationChallenge("hello world".getBytes("UTF-8"))
                            .build());

            /* Generate the key pair. This will result in calls to both generate_key() and
            attest_key() at the keymaster2 HAL. */
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Ottieni la chiave pubblica e privata dal KeyStore
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            KeyFactory factory = KeyFactory.getInstance(publicKey.getAlgorithm(), "AndroidKeyStore");
            KeyInfo keyInfo = factory.getKeySpec(privateKey, KeyInfo.class);

            // Verifica se la chiave è protetta da TEE o HBKP
            boolean isInsideSecureHardware = keyInfo.isInsideSecureHardware();

            // inizializzare keyStore
            KeyStore keyStore = null;
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            // Get the certificate chain
            Certificate[] certs = keyStore.getCertificateChain("key1");
            String publicKey0 = Base64.encodeToString(certs[0].getPublicKey().getEncoded(), Base64.DEFAULT);
            String publicKey1 = Base64.encodeToString(certs[1].getPublicKey().getEncoded(), Base64.DEFAULT);
            String publicKey2 = Base64.encodeToString(certs[2].getPublicKey().getEncoded(), Base64.DEFAULT);
            String publicKey3 = Base64.encodeToString(certs[3].getPublicKey().getEncoded(), Base64.DEFAULT);

            textBox.setTextSize(15);
            textBox.setMovementMethod(new ScrollingMovementMethod());
            textBox.setText("privateKey del Keypair è HW-Backed: " + isInsideSecureHardware
                    + "\n\nCERTIFICATE CHAIN\n\n"
                    + "\ncert0\n" + certs[0] + "\n\npublicKey\n\n:" + publicKey0 + "\n\n------------------------------------\n\n"
                    + "\ncert1\n" + certs[1] + "\n\npublicKey\n\n:" + publicKey1 + "\n\n------------------------------------\n\n"
                    + "\ncert2\n" + certs[2] + "\n\npublicKey\n\n:" + publicKey2 + "\n\n------------------------------------\n\n"
                    + "\ncert3\n" + certs[3] + "\n\npublicKey\n\n:" + publicKey3 + "\n\n------------------------------------\n\n"
            );



        }
        catch (Exception e){
                textBox.setTextSize(15);
                textBox.setMovementMethod(new ScrollingMovementMethod());
                textBox.setText("Error: " + e);
        }

    }


}