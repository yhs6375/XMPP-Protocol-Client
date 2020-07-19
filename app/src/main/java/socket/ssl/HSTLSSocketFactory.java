package socket.ssl;

import android.net.SSLCertificateSocketFactory;
import android.util.Log;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.validation.Schema;

/**
 * Created by hosung on 2017-03-16.
 */

public class HSTLSSocketFactory extends SSLSocketFactory{
    SSLSocketFactory internalSSLSocketFactory;
    //SSLCertificateSocketFactory internalSSLSocketFactory;
    public HSTLSSocketFactory(KeyManager[] keyManagers, TrustManager[] trustManagers) throws NoSuchAlgorithmException,KeyStoreException,KeyManagementException{
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers, trustManagers, null);
        internalSSLSocketFactory=sslContext.getSocketFactory();
    }
    @Override
    public SSLSocket createSocket(String host, int port) throws IOException, UnknownHostException {
        InetAddress addr = InetAddress.getByName(host);
        injectHostname(addr, host);
        return enableTLSOnSocket((SSLSocket)internalSSLSocketFactory.createSocket(addr, port));
    }
    @Override
    public SSLSocket createSocket(InetAddress host, int port) throws IOException {
        return enableTLSOnSocket((SSLSocket)internalSSLSocketFactory.createSocket(host, port));
    }
    @Override
    public SSLSocket createSocket(String host, int port, InetAddress localHost, int localPort)
            throws IOException, UnknownHostException {
        return enableTLSOnSocket((SSLSocket)internalSSLSocketFactory.createSocket(host, port,localHost,localPort));
    }
    @Override
    public SSLSocket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
            throws IOException {
        return enableTLSOnSocket((SSLSocket)internalSSLSocketFactory.createSocket(address, port,localAddress,localPort));
    }
    @Override
    public SSLSocket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        injectHostname(s.getInetAddress(), host);
        return enableTLSOnSocket((SSLSocket)internalSSLSocketFactory.createSocket(s,host,port,autoClose));
    }
    @Override
    public String[] getDefaultCipherSuites() {
        return internalSSLSocketFactory.getDefaultCipherSuites();
    }
    @Override
    public String[] getSupportedCipherSuites() {
        return internalSSLSocketFactory.getSupportedCipherSuites();
    }
    private SSLSocket enableTLSOnSocket(SSLSocket ssl) {
        ssl.setEnabledProtocols(ssl.getSupportedProtocols());
        //internalSSLSocketFactory.setHostname(ssl, "test.hodofactory.com");
        return ssl;
    }
    private void injectHostname(InetAddress address, String host) {
        try {
            Field field = InetAddress.class.getDeclaredField("hostName");
            field.setAccessible(true);
            field.set(address, host);
        } catch (Exception ignored) {
        }
    }
}
