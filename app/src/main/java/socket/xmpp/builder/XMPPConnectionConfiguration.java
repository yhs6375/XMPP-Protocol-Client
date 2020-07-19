package socket.xmpp.builder;

import org.jivesoftware.smack.ConnectionConfiguration;

import javax.net.SocketFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;

public class XMPPConnectionConfiguration {
    public static int DEFAULT_CONNECT_TIMEOUT = 30000;
    public static enum SecurityMode {
        required,
        ifpossible,
        disabled
    }
    private final CharSequence username;
    private final String password;
    private final String resource;
    protected final String serviceName;
    public final String host;
    private final String[] enabledSSLProtocols;
    public final int port;
    private final int connectTimeout;
    private final SecurityMode securityMode;
    private final SSLContext customSSLContext;
    private final SocketFactory socketFactory;

    private XMPPConnectionConfiguration(Builder builder){
        username=builder.username;
        password=builder.password;
        resource = builder.resource;
        serviceName = builder.serviceName;
        if (serviceName == null) {
            throw new IllegalArgumentException("Must provide XMPP service name");
        }
        host = builder.host;
        port = builder.port;
        securityMode = builder.securityMode;
        customSSLContext = builder.customSSLContext;
        enabledSSLProtocols = builder.enabledSSLProtocols;
        connectTimeout = builder.connectTimeout;
        socketFactory=builder.socketFactory;
    }
    public SocketFactory getSocketFactory() {
        return this.socketFactory;
    }
    public String getServiceName(){
        return this.serviceName;
    }
    public CharSequence getUsername(){
        return this.username;
    }
    public int getConnectTimeout() {
        return connectTimeout;
    }
    public static Builder builder() {
        return new Builder();
    }
    public static class Builder{
        private SecurityMode securityMode = SecurityMode.ifpossible;
        private CharSequence username;
        private String password;
        private SSLContext customSSLContext;
        private String resource="HS";
        private String serviceName;
        private String host;
        private int port=5222;
        private SocketFactory socketFactory;
        private String[] enabledSSLProtocols=new String[]{"TLSv1","TLSv1.1","TLSv1.2"};
        private int connectTimeout = DEFAULT_CONNECT_TIMEOUT;

        public Builder setUsernameAndPassword(CharSequence username, String password) {
            this.username = username;
            this.password = password;
            return this;
        }
        public Builder setSecurityMode(SecurityMode securityMode) {
            this.securityMode = securityMode;
            return this;
        }
        public Builder setCustomSSLContext(SSLContext context) {
            this.customSSLContext = context;
            return this;
        }
        public Builder setResource(String resource) {
            this.resource = resource;
            return this;
        }
        public Builder setServiceName(String serviceName) {
            this.serviceName = serviceName;
            return this;
        }
        public Builder setHost(String host) {
            this.host = host;
            return this;
        }
        public Builder setPort(int port) {
            this.port = port;
            return this;
        }
        public Builder setEnabledSSLProtocols(String[] enabledSSLProtocols) {
            this.enabledSSLProtocols = enabledSSLProtocols;
            return this;
        }
        public XMPPConnectionConfiguration build() {
            return new XMPPConnectionConfiguration(this);
        }
        public Builder setConnectTimeout(int connectTimeout) {
            this.connectTimeout = connectTimeout;
            return this;
        }
        public Builder setSocketFactory(SocketFactory socketFactory) {
            this.socketFactory = socketFactory;
            return this;
        }
    }
}
