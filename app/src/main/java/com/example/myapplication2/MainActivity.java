package com.example.myapplication2;

import androidx.appcompat.app.AppCompatActivity;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothManager;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.nfc.NfcAdapter;
import android.nfc.NfcManager;
import android.os.Bundle;

import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.HardwarePropertiesManager;
import android.os.UserManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.telecom.PhoneAccountHandle;
import android.telecom.TelecomManager;
import android.telephony.CellInfo;
import android.telephony.TelephonyManager;
import android.telephony.UiccCardInfo;
import android.text.method.ScrollingMovementMethod;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        TextView textBox = findViewById(R.id.textView1);

        /*
        TextView textBox2 = findViewById(R.id.textView2);
        String txt2 = phoneAccountHandle.get(1).getId();
        textBox2.setTextSize(20);
        textBox2.setText("ICCID2:\n" + txt2);

        String txt4 = bm2.getAdapter().getAddress();
        TextView textBox4 = findViewById(R.id.textView4);
        textBox4.setTextSize(20);
        textBox3.setText("Bluetooth adapter address:\n" + txt4);

        TextView textBox4 = findViewById(R.id.textView4);
        textBox4.setTextSize(20);
        */

        // tentativo KEYSTORE


        // Create KeyPairGenerator and set generation parameters for an ECDSA key pair
        // using the NIST P-256 curve.  "Key1" is the key alias.
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

            // inizializzare keyStore
            KeyStore keyStore = null;
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            // Get the certificate chain
            Certificate[] certs = keyStore.getCertificateChain("key1");

            textBox.setTextSize(15);
            textBox.setMovementMethod(new ScrollingMovementMethod());
            textBox.setText("certificate chain\n\n"
                    + "\ncert0\n" + certs[0] + "\n\n ------------------------------------\n\n\n"
                    + "\ncert1\n" + certs[1] + "\n\n ------------------------------------\n\n\n"
                    + "\ncert2\n" + certs[2] + "\n\n ------------------------------------\n\n\n"
                    + "\ncert3\n" + certs[3] + "\n\n ------------------------------------\n\n\n"
            );

            // certs[0] is the attestation certificate. certs[1] signs certs[0], etc.,
            // up to certs[certs.length - 1].

            /*
            PublicKey pk = certs[0].getPublicKey();
            String pk_s = Base64.getEncoder().encodeToString(pk.getEncoded());

            String esito;
            // VERIFICA DEL CERTIFICAT0
            if (validateCertificate((X509Certificate) certs[0]) == true) {
                esito = "Valido";
            } else {
                esito = "NON Valido";
            }
            */

        }catch (Exception e){
                textBox.setTextSize(15);
                textBox.setMovementMethod(new ScrollingMovementMethod());
                textBox.setText("Error: " + e);
        }
        /*catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        } catch (NoSuchProviderException ex) {
            throw new RuntimeException(ex);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new RuntimeException(ex);
        } catch (UnsupportedEncodingException ex) {
            throw new RuntimeException(ex);
        } catch (KeyStoreException ex) {
            throw new RuntimeException(ex);
        } catch (CertificateException ex) {
            throw new RuntimeException(ex);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }*/


    }

    /*
    public static boolean validateCertificate(X509Certificate certificate) {
        try {
            // Load the trusted CA certificates from a KeyStore
            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            trustStore.load(null);  // Load your trusted CA certificates here

            // Create a TrustManagerFactory with the trusted CA certificates
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // Get the X509TrustManager from the TrustManagerFactory
            X509TrustManager trustManager = findX509TrustManager(trustManagerFactory);

            System.out.println(trustManager);

            // Validate the certificate
            trustManager.checkServerTrusted(new X509Certificate[]{certificate}, "RSA");
            return true;  // Certificate is valid

        } catch (Exception e) {
            e.printStackTrace();
            return false;  // Certificate is not valid
        }
    }

    private static X509TrustManager findX509TrustManager(TrustManagerFactory trustManagerFactory) throws CertificateException {
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
        for (TrustManager trustManager : trustManagers) {
            if (trustManager instanceof X509TrustManager) {
                return (X509TrustManager) trustManager;
            }
        }
        throw new CertificateException("No X509TrustManager found");
    }

    public void checkPermission(String permission, int requestCode)
    {
        if (ContextCompat.checkSelfPermission(MainActivity.this, permission) == PackageManager.PERMISSION_DENIED) {

            // Requesting the permission
            ActivityCompat.requestPermissions(MainActivity.this, new String[] { permission }, requestCode);
        }
        else {
            Toast.makeText(MainActivity.this, "Permission already granted", Toast.LENGTH_SHORT).show();
        }
    }
    */
}