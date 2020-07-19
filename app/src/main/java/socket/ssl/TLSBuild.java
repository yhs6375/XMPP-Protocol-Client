package socket.ssl;

import android.content.Context;
import android.util.Log;

import com.test.hosung.projectapp.R;

import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.X509CertificateStructure;
import org.spongycastle.jce.provider.X509CertificateObject;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * Created by hosung on 2017-03-16.
 */

public class TLSBuild {
    KeyManager[] keyManagers=null;
    TrustManager[] trustManagers=null;

    public void KeyAndTrustSet(KeyManager[] keyManagers, TrustManager[] trustManagers){
        this.keyManagers=keyManagers;
        this.trustManagers=trustManagers;
    }
    public void KeyAndTrustSetDefault() throws CertificateException,KeyStoreException,NoSuchAlgorithmException,IOException,UnrecoverableKeyException{
        try{
            KeyStore androidStore=KeyStore.getInstance("AndroidKeyStore");
            androidStore.load(null,null);
            KeyStore.Entry clientEntry=androidStore.getEntry("clientCert",null);
            Certificate caCert=androidStore.getCertificate("CAcert");

            KeyStore keyStore=KeyStore.getInstance("PKCS12"); //KeyStore는 서버에게 신뢰받은 유저라는걸 증명하기위해 사용한다.
            keyStore.load(null,null);
            keyStore.setEntry("clientCert",clientEntry,null);
            KeyManagerFactory kmf=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

            kmf.init(keyStore,null);
            keyManagers=kmf.getKeyManagers();

            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());//TrustStore는 서버가 신뢰할 수 있는지 확인하기위해 사용된다.(rootCA)
            trustStore.load(null,null);
            trustStore.setCertificateEntry("CA",caCert);
            TrustManagerFactory tmf=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            trustManagers=tmf.getTrustManagers();
        }catch(UnrecoverableEntryException e){
            Log.d("HS","Cannot find entry.");
        }
    }
    public HSTLSSocketFactory createSocketFactory() throws CertificateException,UnrecoverableKeyException,NoSuchAlgorithmException,KeyStoreException,KeyManagementException,IOException{
        if(keyManagers==null||trustManagers==null){
            KeyAndTrustSetDefault();
        }
        return new HSTLSSocketFactory(keyManagers,trustManagers);
    }
    public SSLContext createContext() throws CertificateException,UnrecoverableKeyException,NoSuchAlgorithmException,KeyStoreException,KeyManagementException,IOException{
        if(keyManagers==null||trustManagers==null){
            KeyAndTrustSetDefault();
        }
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers, trustManagers, null);
        return sslContext;
    }
    public SSLSocket createSocket(String host, int port) throws CertificateException,UnrecoverableKeyException,NoSuchAlgorithmException,KeyStoreException,KeyManagementException,IOException{
        if(keyManagers==null||trustManagers==null){
            KeyAndTrustSetDefault();
        }
        HSTLSSocketFactory socketFactory=new HSTLSSocketFactory(keyManagers,trustManagers);
        return socketFactory.createSocket(host,port);
    }
}
