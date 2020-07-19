package socket.ssl;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.support.annotation.MainThread;
import android.util.Log;

import socket.HSSocketClient;

import org.spongycastle.operator.OperatorCreationException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import util.HSTask;

public class TLSInitiateKey {
    String CAcert="-----BEGIN CERTIFICATE-----\n" +
            "MIIFkzCCA3ugAwIBAgIJANZXDx3HK8FzMA0GCSqGSIb3DQEBCwUAMGAxCzAJBgNV\n" +
            "BAYTAktSMQ4wDAYDVQQIDAVTZW91bDEQMA4GA1UEBwwHZG9uZ2phazEjMCEGA1UE\n" +
            "CgwaQUNNRSBTaWduaW5nIEF1dGhvcml0eSBJbmMxCjAIBgNVBAMMAS4wHhcNMTcw\n" +
            "MzE4MDk1NjMwWhcNMTgwMzE4MDk1NjMwWjBgMQswCQYDVQQGEwJLUjEOMAwGA1UE\n" +
            "CAwFU2VvdWwxEDAOBgNVBAcMB2RvbmdqYWsxIzAhBgNVBAoMGkFDTUUgU2lnbmlu\n" +
            "ZyBBdXRob3JpdHkgSW5jMQowCAYDVQQDDAEuMIICIjANBgkqhkiG9w0BAQEFAAOC\n" +
            "Ag8AMIICCgKCAgEAvkIg8kwpkhAlET0IaqKryli+tD2z80GzkscPy6Lh1M8ozoR5\n" +
            "FfUAJRCLBjY00CAoM8zDEe437XM16Cddx7IST4lY2YxkzMPrlqu8AFRAeK6Q1RFf\n" +
            "Ysec6ekkBPUEh7qbS8g7xwcKq7tC2IeyK5UexJq9Jhfw4HCbIAF03DVBibnldY2t\n" +
            "nkR1ze7QFMx4xwosLOFk966/jOzTlSYBu0IMR7x8t16TlFPDIap43n2a987p6ik+\n" +
            "vtF95YFnRdps1Ov+0vSixbRQB8oFHDigCe+clpZJEpMFt/vuv0Or7VIhkLwSl3q8\n" +
            "hUMa77WtC9ChOk8787FyvcPEB9Y0+awDoRGywhnSD2xekXzMOxNSArma12gBTtgS\n" +
            "vFINUQD0hCS575NC8DS/bVLAgje1HmLHG5pgNHG8neKp/24+xhdmV4VrfGXNlFSh\n" +
            "Vc2Pv6og7jyGIUOzuw+NM1xnKFFRbvHxTXOBqNeUTsbS86v3lSmOPVkbbkRZ5ent\n" +
            "vRPQDPgN9zEQ8+kmx+S2FabBlx8NviMLc1HvFU/xSIypJaChGuyu7KUeoeiN61fT\n" +
            "WANmkMXjWxu6LWwu8lRddjj7ABQHAM4I8ViRHnguLIcAfypP77nt7QHeaLwPcKdr\n" +
            "zjbvk3qQLO+64KRM3A3hmSAp0wZMXFFWUzlMzHmx+nhYYrGeKz9GCveFwPMCAwEA\n" +
            "AaNQME4wHQYDVR0OBBYEFOYh4i6pYBPCJzWYpkW6lgpxrBk0MB8GA1UdIwQYMBaA\n" +
            "FOYh4i6pYBPCJzWYpkW6lgpxrBk0MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEL\n" +
            "BQADggIBAHqlpE8FiU9v24wUiLT+vNaGGvr6I3vrE182qVEfZuhsBlxUgVdTe7Kh\n" +
            "fc2vFwU0A+ZZyDx8KnLj4atixoJvSGftV3mmONe9+1mQ5VKf4oVp7eBDGUfZLgSb\n" +
            "RTwxx8lK6wtZG9JJSsXSCTChjNJgdY/wma83wxf3AJCc/6Qq7ImNHBjTxRGKg57u\n" +
            "jYubpizahpkyCNyaQTQZiYISFwkke6qhtu1y8oGmyzamx0TYel7w53OjYUjFVI2q\n" +
            "VqgAZBhfGY6h9qWmunJi7WF0SHCraHT33raiSvRvSGKSi7cTgLtOmxM8mln50BVg\n" +
            "CHcsw2twnxYYfnOCkrU1mzBa5k+kv+KF5odNG4VRK5QahBhaccGX57bUwYjE8wgM\n" +
            "vBUWKMytk6s8aG2iEu5J1vGkzKHYO3RQWgu5QT5AruBoCgkTNukGLAXafCTVIqvU\n" +
            "qArYakg9cy1Zf6+FvLeUZ+Z+V6leP4XIYVeJnBmTNT/Zw28PpCAftMnpmN5i7WD5\n" +
            "dKSmyLS/HQmNeHCRvN1u2vqxjUVuYixzmAaLqEXF7UmC3ckVaWh/zNy/glyOwlcu\n" +
            "4j7hp5PqElUmGn2NlZWntMF8rumN4AHFPnxsKLokk0slXrxK7HLEnxbnYJRP9zS9\n" +
            "t65eh/3j1P/h8bF9JeUnfFoVZ+Nr2pQdpEKyCeWufy6YeiIPSUu0\n" +
            "-----END CERTIFICATE-----";
    private Context context;
    private byte[] certByte;
    private KeyPair clientKey;
    private Callback listener;
    private KeyStore androidStore;
    public TLSInitiateKey(final Context context){
        this.context=context;
        try {
            clientKey = MakeKeyPairAndCSR.makeKeyPair();
            final byte[] clientCSR = MakeKeyPairAndCSR.makeCSR(clientKey);

            final HSSocketClient socketClient=new HSSocketClient("test.hodofactory.com",8109);
            socketClient.setClientCallback(new HSSocketClient.ClientCallback(){
                @Override
                public void onConnect(Socket socket){
                    Log.d("HS","연결");
                    socketClient.send(clientCSR);
                }
                @Override
                public void onDisconnect(String message){
                    Log.d("HS","연결 끝");
                }
                @Override
                public void onConnectError(Socket socket,String Message){
                }
                @Override
                public void onReceive(byte[] data){
                    storeData(data);
                    socketClient.disconnect();
                    certByte=data;
                    new TestHandler().obtainMessage(0).sendToTarget();
                }
            });
            socketClient.connect();
        }catch(NoSuchAlgorithmException e){
            Log.d("HS","11NoSuchAlgorithm관련 : "+e.getMessage());e.printStackTrace();
        }catch(IOException e){
            Log.d("HS","11IOException관련 : "+e.getMessage());e.printStackTrace();
        }catch(OperatorCreationException e){
            Log.d("HS","11OperatorCreationException관련 : "+e.getMessage());e.printStackTrace();
        }
    }
    private void storeData(byte[] clientCertData){
        try{
            androidStore=KeyStore.getInstance("AndroidKeyStore");
            Log.d("HS","StoreData2");
            androidStore.load(null,null);
            Log.d("HS","StoreData3");
            if(!androidStore.containsAlias("CAcert")||!androidStore.containsAlias("clientCert")){
                ByteArrayInputStream derInputStream = new ByteArrayInputStream(CAcert.getBytes());
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(derInputStream);
                androidStore.setCertificateEntry("CAcert", cert);

                ByteArrayInputStream keyDerInputStream = new ByteArrayInputStream(clientCertData);
                CertificateFactory clientCertificateFactory = CertificateFactory.getInstance("X.509");
                X509Certificate clientCert = (X509Certificate) clientCertificateFactory.generateCertificate(keyDerInputStream);
                Certificate[] certChain = new Certificate[2];
                certChain[0] = clientCert;
                certChain[1]=cert;
                androidStore.setKeyEntry("clientCert",clientKey.getPrivate(),null,certChain);
            }
            Log.d("HS","StoreData4");
        }catch(CertificateException e){
            Log.d("HS","Cert관련 : "+e.getMessage());e.printStackTrace();
        }catch(KeyStoreException e){
            Log.d("HS","KeyStore관련 : "+e.getMessage());e.printStackTrace();
        }catch(NoSuchAlgorithmException e){
            Log.d("HS","NoSuchAlgorithm관련 : "+e.getMessage());e.printStackTrace();
        }catch(IOException e){
            Log.d("HS","IOException관련 : "+e.getMessage());e.printStackTrace();
        }
    }
    private class TestHandler extends Handler {
        public TestHandler() {
            super(Looper.getMainLooper());
        }
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case 0:
                    listener.onSuccess();
            }
        }
    }
    public void setCallback(Callback listener){
        this.listener=listener;
    }
    public interface Callback{
        void onSuccess();
        void onError();
    }
}
