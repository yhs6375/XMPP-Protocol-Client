package com.test.hosung.projectapp;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.io.IOException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Enumeration;

import javax.security.auth.x500.X500Principal;

/**
 * Created by hosung on 2017-03-13.
 */

public class KeyManager {
    static private KeyStore keyStore;
    public KeyManager(){
        try{
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
        }catch(KeyStoreException e){

        }catch(IOException e){

        }catch(NoSuchAlgorithmException e){

        }catch(CertificateException e){

        }
    }
    public void refreshKeys() {
        ArrayList keyAliases = new ArrayList<>();
        try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String a=aliases.nextElement();
                keyAliases.add(a);
            }
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry("authority", null);
            RSAPublicKey publicKey=(RSAPublicKey)privateKeyEntry.getCertificate().getPublicKey();
        }
        catch(Exception e) {}
    }
    static public void createNewKeys(Context context,String alias) {
        KeyPairGenerator generator=null;
        try {
            if(!keyStore.containsAlias(alias)){
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 1);
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
                if(android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M){
                    Log.d("HS","Current version is 23(MashMello)");
                    //Api level 23
                    KeyGenParameterSpec spec = new  KeyGenParameterSpec.Builder(
                            alias,
                            KeyProperties.PURPOSE_DECRYPT)
                            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                            .build();
                    generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
                    generator.initialize(spec);
                }else{
                    Log.d("HS","Current version is < 23(MashMello)");
                    //api level 17+ 4.4.3
                    KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                            .setAlias("key1")
                            .setSubject(new X500Principal("CN=Sample Name, O=Android Authority"))
                            .setSerialNumber(BigInteger.ONE)
                            .setStartDate(start.getTime())
                            .setEndDate(end.getTime())
                            .build();
                    generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
                    generator.initialize(spec);
                }
                KeyPair keyPair = generator.generateKeyPair();
            }
        } catch (Exception e) {
            Log.d("HS", "Exception " + e.getMessage() + " occured");
            Log.e("HS", Log.getStackTraceString(e));
        }
        //refreshKeys();
    }
}
