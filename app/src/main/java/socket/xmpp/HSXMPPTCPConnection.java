package socket.xmpp;

import android.util.Log;

import socket.HSSocketException;
import socket.xmpp.builder.AbstractConnectionListener;
import org.jivesoftware.smack.ConnectionConfiguration;
import org.jivesoftware.smack.ConnectionConfiguration.SecurityMode;
import org.jivesoftware.smack.ConnectionCreationListener;
import org.jivesoftware.smack.StanzaListener;
import org.jivesoftware.smack.SmackConfiguration;
import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.SmackException.AlreadyLoggedInException;
import org.jivesoftware.smack.SmackException.NoResponseException;
import org.jivesoftware.smack.SmackException.SecurityRequiredByClientException;
import org.jivesoftware.smack.SmackException.SecurityRequiredByServerException;
import org.jivesoftware.smack.XMPPException.StreamErrorException;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.XMPPException.XMPPErrorException;
import org.jivesoftware.smack.compress.packet.Compressed;
import org.jivesoftware.smack.compression.XMPPInputOutputStream;
import org.jivesoftware.smack.filter.StanzaFilter;
import org.jivesoftware.smack.compress.packet.Compress;
import org.jivesoftware.smack.packet.IQ;
import org.jivesoftware.smack.packet.Message;
import org.jivesoftware.smack.packet.Stanza;
import org.jivesoftware.smack.packet.Presence;
import org.jivesoftware.smack.packet.StartTls;
import org.jivesoftware.smack.sasl.packet.SaslStreamElements;
import org.jivesoftware.smack.sasl.packet.SaslStreamElements.Challenge;
import org.jivesoftware.smack.sasl.packet.SaslStreamElements.SASLFailure;
import org.jivesoftware.smack.sasl.packet.SaslStreamElements.Success;
import org.jivesoftware.smack.sm.SMUtils;
import org.jivesoftware.smack.sm.StreamManagementException.StreamIdDoesNotMatchException;
import org.jivesoftware.smack.sm.StreamManagementException.StreamManagementCounterError;
import org.jivesoftware.smack.sm.StreamManagementException.StreamManagementNotEnabledException;
import org.jivesoftware.smack.sm.packet.StreamManagement;
import org.jivesoftware.smack.sm.packet.StreamManagement.AckAnswer;
import org.jivesoftware.smack.sm.packet.StreamManagement.AckRequest;
import org.jivesoftware.smack.sm.packet.StreamManagement.Enable;
import org.jivesoftware.smack.sm.packet.StreamManagement.Enabled;
import org.jivesoftware.smack.sm.packet.StreamManagement.Failed;
import org.jivesoftware.smack.sm.packet.StreamManagement.Resume;
import org.jivesoftware.smack.sm.packet.StreamManagement.Resumed;
import org.jivesoftware.smack.sm.packet.StreamManagement.StreamManagementFeature;
import org.jivesoftware.smack.sm.predicates.Predicate;
import org.jivesoftware.smack.sm.provider.ParseStreamManagement;
import org.jivesoftware.smack.packet.XMPPError;
import org.jivesoftware.smack.tcp.XMPPTCPConnection;
import org.jivesoftware.smack.util.Async;
import org.jivesoftware.smack.util.PacketParserUtils;
import org.jivesoftware.smack.util.XmlStringBuilder;
import org.jivesoftware.smack.util.dns.HostAddress;
import org.jxmpp.util.XmppStringUtils;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import javax.net.SocketFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.lang.reflect.Constructor;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;

import socket.xmpp.builder.ConnectionListener;
import socket.xmpp.builder.XMPPConnectionConfiguration;
import HS.xml.Element;
import socket.xmpp.packet.StreamOpen;
import socket.xmpp.sasl.SASLAuthentication;
import socket.xmpp.util.ArrayBlockingQueueWithShutdown;
import socket.xmpp.util.XMPPStringUtils;
import util.HSTask;

import socket.HSSocketException.AlreadyConnectedException;
import socket.HSSocketException.NotConnectedException;
import socket.HSSocketException.ConnectionException;

public class HSXMPPTCPConnection{
    private static final int QUEUE_SIZE = 500;
    private static final Logger LOGGER = Logger.getLogger(org.jivesoftware.smack.tcp.XMPPTCPConnection.class.getName());
    private Socket socket;
    private boolean disconnectedButResumeable = false;
    private volatile boolean socketClosed = false;
    private boolean usingTLS = false;
    protected PacketWriter packetWriter;
    protected PacketReader packetReader;
    private final SynchronizationPoint<Exception> initalOpenStreamSend = new SynchronizationPoint<Exception>(this);
    private final SynchronizationPoint<XMPPException> maybeCompressFeaturesReceived = new SynchronizationPoint<XMPPException>(this);
    private final SynchronizationPoint<XMPPException> compressSyncPoint = new SynchronizationPoint<XMPPException>(this);
    private static BundleAndDeferCallback defaultBundleAndDeferCallback;
    private BundleAndDeferCallback bundleAndDeferCallback = defaultBundleAndDeferCallback;
    private static boolean useSmDefault = false;
    private static boolean useSmResumptionDefault = true;
    private String smSessionId;
    private final SynchronizationPoint<XMPPException> smResumedSyncPoint = new SynchronizationPoint<XMPPException>(this);
    private final SynchronizationPoint<XMPPException> smEnabledSyncPoint = new SynchronizationPoint<XMPPException>(this);
    private int smClientMaxResumptionTime = -1;
    private int smServerMaxResumptimTime = -1;
    private boolean useSm = useSmDefault;
    private boolean useSmResumption = useSmResumptionDefault;
    private long serverHandledStanzasCount = 0;
    private long clientHandledStanzasCount = 0;
    private BlockingQueue<Stanza> unacknowledgedStanzas;
    private boolean smWasEnabledAtLeastOnce = false;
    private final Collection<StanzaListener> stanzaAcknowledgedListeners = new ConcurrentLinkedQueue<StanzaListener>();
    private final Map<String, StanzaListener> stanzaIdAcknowledgedListeners = new ConcurrentHashMap<String, StanzaListener>();
    private final Set<StanzaFilter> requestAckPredicates = new LinkedHashSet<StanzaFilter>();
    protected final XMPPConnectionConfiguration config;
    protected boolean authenticated = false;
    protected boolean connected = false;
    protected final Set<ConnectionListener> connectionListeners = new CopyOnWriteArraySet<ConnectionListener>();
    protected List<HostAddress> hostAddresses;
    protected XMPPInputOutputStream compressionHandler;
    protected Writer writer;
    protected Reader reader;
    protected final Lock connectionLock = new ReentrantLock();
    private String serviceName;
    protected String streamId;
    private long packetReplyTimeout = 5000;
    protected SASLAuthentication saslAuthentication = new SASLAuthentication(this);
    protected final SynchronizationPoint<HSSocketException> saslFeatureReceived = new SynchronizationPoint<HSSocketException>(HSXMPPTCPConnection.this);
    protected final SynchronizationPoint<Exception> lastFeaturesReceived = new SynchronizationPoint<Exception>(HSXMPPTCPConnection.this);

    public HSXMPPTCPConnection(XMPPConnectionConfiguration config){
        this.config = config;
        addConnectionListener(new AbstractConnectionListener() {
            @Override
            public void connectionClosedOnError(Exception e) {
                if (e instanceof StreamErrorException) {
                    dropSmState();
                }
            }
        });
    }
    public HSXMPPTCPConnection(CharSequence jid, String password) {
        this(XmppStringUtils.parseLocalpart(jid.toString()), password, XmppStringUtils.parseDomain(jid.toString()));
    }

    public HSXMPPTCPConnection(CharSequence username, String password, String serviceName) {
        this(XMPPConnectionConfiguration.builder().setUsernameAndPassword(username, password).setServiceName(
                serviceName).build());
    }
    public void addConnectionListener(ConnectionListener connectionListener) {
        if (connectionListener == null) {
            return;
        }
        connectionListeners.add(connectionListener);
    }
    public final boolean isAuthenticated() {
        return authenticated;
    }
    public final boolean isConnected() {
        return connected;
    }
    public synchronized HSXMPPTCPConnection connect() throws HSSocketException, IOException, XMPPException {
        // 이미 연결이 되어있지않은지 체크
        throwAlreadyConnectedExceptionIfAppropriate();
        // 연결상태 리셋
        saslAuthentication.init();
        saslFeatureReceived.init();
        lastFeaturesReceived.init();
        streamId = null;
        // XMPP 실제 연결 수행
        connectInternal();
        return this;
    }
    protected void throwNotConnectedExceptionIfAppropriate() throws NotConnectedException {
        if (packetWriter == null) {
            throw new SmackException.NotConnectedException();
        }
        packetWriter.throwNotConnectedExceptionIfDoneAndResumptionNotPossible();
    }

    protected void throwAlreadyConnectedExceptionIfAppropriate() throws AlreadyConnectedException {
        if (isConnected() && !disconnectedButResumeable) {
            throw new AlreadyConnectedException();
        }
    }

    protected void throwAlreadyLoggedInExceptionIfAppropriate() throws AlreadyLoggedInException {
        if (isAuthenticated() && !disconnectedButResumeable) {
            throw new AlreadyLoggedInException();
        }
    }

    protected void afterSuccessfulLogin(final boolean resumed) throws NotConnectedException {
        // Reset the flag in case it was set
        disconnectedButResumeable = false;
        super.afterSuccessfulLogin(resumed);
    }

    @Override
    protected synchronized void loginNonAnonymously(String username, String password, String resource) throws XMPPException, SmackException, IOException {
        if (saslAuthentication.hasNonAnonymousAuthentication()) {
            // Authenticate using SASL
            if (password != null) {
                saslAuthentication.authenticate(username, password, resource);
            }
            else {
                saslAuthentication.authenticate(resource, config.getCallbackHandler());
            }
        } else {
            throw new SmackException("No non-anonymous SASL authentication mechanism available");
        }

        // If compression is enabled then request the server to use stream compression. XEP-170
        // recommends to perform stream compression before resource binding.
        if (config.isCompressionEnabled()) {
            useCompression();
        }

        if (isSmResumptionPossible()) {
            smResumedSyncPoint.sendAndWaitForResponse(new Resume(clientHandledStanzasCount, smSessionId));
            if (smResumedSyncPoint.wasSuccessful()) {
                // We successfully resumed the stream, be done here
                afterSuccessfulLogin(true);
                return;
            }
            // SM resumption failed, what Smack does here is to report success of
            // lastFeaturesReceived in case of sm resumption was answered with 'failed' so that
            // normal resource binding can be tried.
            LOGGER.fine("Stream resumption failed, continuing with normal stream establishment process");
        }

        List<Stanza> previouslyUnackedStanzas = new LinkedList<Stanza>();
        if (unacknowledgedStanzas != null) {
            // There was a previous connection with SM enabled but that was either not resumable or
            // failed to resume. Make sure that we (re-)send the unacknowledged stanzas.
            unacknowledgedStanzas.drainTo(previouslyUnackedStanzas);
            // Reset unacknowledged stanzas to 'null' to signal that we never send 'enable' in this
            // XMPP session (There maybe was an enabled in a previous XMPP session of this
            // connection instance though). This is used in writePackets to decide if stanzas should
            // be added to the unacknowledged stanzas queue, because they have to be added right
            // after the 'enable' stream element has been sent.
            dropSmState();
        }

        // Now bind the resource. It is important to do this *after* we dropped an eventually
        // existing Stream Management state. As otherwise <bind/> and <session/> may end up in
        // unacknowledgedStanzas and become duplicated on reconnect. See SMACK-706.
        bindResourceAndEstablishSession(resource);

        if (isSmAvailable() && useSm) {
            // Remove what is maybe left from previously stream managed sessions
            serverHandledStanzasCount = 0;
            // XEP-198 3. Enabling Stream Management. If the server response to 'Enable' is 'Failed'
            // then this is a non recoverable error and we therefore throw an exception.
            smEnabledSyncPoint.sendAndWaitForResponseOrThrow(new Enable(useSmResumption, smClientMaxResumptionTime));
            synchronized (requestAckPredicates) {
                if (requestAckPredicates.isEmpty()) {
                    // Assure that we have at lest one predicate set up that so that we request acks
                    // for the server and eventually flush some stanzas from the unacknowledged
                    // stanza queue
                    requestAckPredicates.add(Predicate.forMessagesOrAfter5Stanzas());
                }
            }
        }
        // (Re-)send the stanzas *after* we tried to enable SM
        for (Stanza stanza : previouslyUnackedStanzas) {
            sendStanzaInternal(stanza);
        }

        afterSuccessfulLogin(false);
    }

    @Override
    public synchronized void loginAnonymously() throws XMPPException, SmackException, IOException {
        // Wait with SASL auth until the SASL mechanisms have been received
        saslFeatureReceived.checkIfSuccessOrWaitOrThrow();

        if (saslAuthentication.hasAnonymousAuthentication()) {
            saslAuthentication.authenticateAnonymously();
        }
        else {
            throw new SmackException("No anonymous SASL authentication mechanism available");
        }

        // If compression is enabled then request the server to use stream compression
        if (config.isCompressionEnabled()) {
            useCompression();
        }

        bindResourceAndEstablishSession(null);

        afterSuccessfulLogin(false);
    }

    @Override
    w

    public boolean isSocketClosed() {
        return socketClosed;
    }

    /**
     * Shuts the current connection down. After this method returns, the connection must be ready
     * for re-use by connect.
     */
    @Override
    protected void shutdown() {
        if (isSmEnabled()) {
            try {
                // Try to send a last SM Acknowledgement. Most servers won't find this information helpful, as the SM
                // state is dropped after a clean disconnect anyways. OTOH it doesn't hurt much either.
                sendSmAcknowledgementInternal();
            } catch (SmackException.NotConnectedException e) {
                LOGGER.log(Level.FINE, "Can not send final SM ack as connection is not connected", e);
            }
        }
        shutdown(false);
    }

    /**
     * Performs an unclean disconnect and shutdown of the connection. Does not send a closing stream stanza.
     */
    public synchronized void instantShutdown() {
        shutdown(true);
    }

    private void shutdown(boolean instant) {
        if (disconnectedButResumeable) {
            return;
        }
        if (packetReader != null) {
            packetReader.shutdown();
        }
        if (packetWriter != null) {
            packetWriter.shutdown(instant);
        }

        // Set socketClosed to true. This will cause the PacketReader
        // and PacketWriter to ignore any Exceptions that are thrown
        // because of a read/write from/to a closed stream.
        // It is *important* that this is done before socket.close()!
        socketClosed = true;
        try {
            socket.close();
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "shutdown", e);
        }

        setWasAuthenticated();
        // If we are able to resume the stream, then don't set
        // connected/authenticated/usingTLS to false since we like behave like we are still
        // connected (e.g. sendStanza should not throw a NotConnectedException).
        if (isSmResumptionPossible() && instant) {
            disconnectedButResumeable = true;
        } else {
            disconnectedButResumeable = false;
            // Reset the stream management session id to null, since if the stream is cleanly closed, i.e. sending a closing
            // stream tag, there is no longer a stream to resume.
            smSessionId = null;
        }
        authenticated = false;
        connected = false;
        usingTLS = false;
        reader = null;
        writer = null;

        maybeCompressFeaturesReceived.init();
        compressSyncPoint.init();
        smResumedSyncPoint.init();
        smEnabledSyncPoint.init();
        initalOpenStreamSend.init();
    }

    public void send(Element element) throws NotConnectedException {
        packetWriter.sendStreamElement(element);
    }

    protected void sendStanzaInternal(Stanza packet) throws SmackException.NotConnectedException {
        packetWriter.sendStreamElement(packet);
        if (isSmEnabled()) {
            for (StanzaFilter requestAckPredicate : requestAckPredicates) {
                if (requestAckPredicate.accept(packet)) {
                    requestSmAcknowledgementInternal();
                    break;
                }
            }
        }
    }
    private void connectUsingConfiguration() throws IOException, ConnectionException {
        InetAddress inetAddress=null;
        SocketFactory socketFactory = config.getSocketFactory();
        String errorMsg="";
        if (socketFactory == null) {
            socketFactory = SocketFactory.getDefault();
        }
        String host=config.host;
        int port = config.port;
        socket = socketFactory.createSocket();
        try {
            Iterator<InetAddress> inetAddresses = Arrays.asList(InetAddress.getAllByName(host)).iterator();
            if (!inetAddresses.hasNext()){
                throw new UnknownHostException(host);
            }
            innerloop: while (inetAddresses.hasNext()) {
                inetAddress = inetAddresses.next();
                socket = socketFactory.createSocket();
                final String inetAddressAndPort = inetAddress + " at port " + port;
                LOGGER.finer("Trying to establish TCP connection to " + inetAddressAndPort);
                try {
                    socket.connect(new InetSocketAddress(inetAddress, port), config.getConnectTimeout());
                }catch(Exception e){
                    if (inetAddresses.hasNext()) {
                        continue innerloop;
                    } else {
                        throw e;
                    }
                }
                LOGGER.finer("Established TCP connection to " + inetAddressAndPort);
                // We found a host to connect to, return here
                //this.host = host;
                //this.port = port;
                return;
            }
        }catch(UnknownHostException e){
            errorMsg="InetAddress.getAllByName() returned empty result array.";
        } catch (Exception e) {
            errorMsg=host+port+e.getMessage();
        }
        ConnectionException errorObj=new ConnectionException(errorMsg);
        errorObj.setFailedAddress(inetAddress);
        throw new ConnectionException(errorMsg);
    }

    private void initConnection() throws IOException {
        Log.d("HS","initConnection");
        boolean isFirstInitialization = packetReader == null || packetWriter == null;
        compressionHandler = null;
        // reader와 writer를 설정
        initReaderAndWriter();
        if (isFirstInitialization) {
            packetWriter = new PacketWriter();
            packetReader = new PacketReader();
        }
        Log.d("HS","initConnection2222");
        // packet writer 시작.이 부분에서 서버로의 XMPP Stream을 오픈 할 것이다.
        packetWriter.init();
        // Start the packet reader. The startup() method will block until we
        // get an opening stream packet back from server
        packetReader.init();
        Log.d("HS","initConnection3333");
        if (isFirstInitialization) {
            // Notify listeners that a new connection has been established
            for (ConnectionCreationListener listener : getConnectionCreationListeners()) {
                Log.d("HS","initConnection4444");
                listener.connectionCreated(this);
            }
        }
    }

    private void initReaderAndWriter() throws IOException {
        InputStream is = socket.getInputStream();
        OutputStream os = socket.getOutputStream();
        if (compressionHandler != null) {
            is = compressionHandler.getInputStream(is);
            os = compressionHandler.getOutputStream(os);
        }
        // OutputStreamWriter is already buffered, no need to wrap it into a BufferedWriter
        writer = new OutputStreamWriter(os, "UTF-8");
        reader = new BufferedReader(new InputStreamReader(is, "UTF-8"));
    }

    /**
     * The server has indicated that TLS negotiation can start. We now need to secure the
     * existing plain connection and perform a handshake. This method won't return until the
     * connection has finished the handshake or an error occurred while securing the connection.
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws KeyStoreException
     * @throws UnrecoverableKeyException
     * @throws KeyManagementException
     * @throws SmackException
     * @throws Exception if an exception occurs.
     */
    private void proceedTLSReceived() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException, NoSuchProviderException, UnrecoverableKeyException, KeyManagementException, SmackException {
        Log.d("HS","proceedTLSReceived");
        SSLContext context = this.config.getCustomSSLContext();
        KeyStore ks = null;
        KeyManager[] kms = null;
        PasswordCallback pcb = null;

        if(config.getCallbackHandler() == null) {
            ks = null;
        } else if (context == null) {
            if(config.getKeystoreType().equals("NONE")) {
                ks = null;
                pcb = null;
            }
            else if(config.getKeystoreType().equals("PKCS11")) {
                try {
                    Constructor<?> c = Class.forName("sun.security.pkcs11.SunPKCS11").getConstructor(InputStream.class);
                    String pkcs11Config = "name = SmartCard\nlibrary = "+config.getPKCS11Library();
                    ByteArrayInputStream config = new ByteArrayInputStream(pkcs11Config.getBytes());
                    Provider p = (Provider)c.newInstance(config);
                    Security.addProvider(p);
                    ks = KeyStore.getInstance("PKCS11",p);
                    pcb = new PasswordCallback("PKCS11 Password: ",false);
                    this.config.getCallbackHandler().handle(new Callback[]{pcb});
                    ks.load(null,pcb.getPassword());
                }
                catch (Exception e) {
                    ks = null;
                    pcb = null;
                }
            }
            else if(config.getKeystoreType().equals("Apple")) {
                ks = KeyStore.getInstance("KeychainStore","Apple");
                ks.load(null,null);
                //pcb = new PasswordCallback("Apple Keychain",false);
                //pcb.setPassword(null);
            }
            else {
                ks = KeyStore.getInstance(config.getKeystoreType());
                try {
                    pcb = new PasswordCallback("Keystore Password: ",false);
                    config.getCallbackHandler().handle(new Callback[]{pcb});
                    ks.load(new FileInputStream(config.getKeystorePath()), pcb.getPassword());
                }
                catch(Exception e) {
                    ks = null;
                    pcb = null;
                }
            }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            try {
                if(pcb == null) {
                    kmf.init(ks,null);
                } else {
                    kmf.init(ks,pcb.getPassword());
                    pcb.clearPassword();
                }
                kms = kmf.getKeyManagers();
            } catch (NullPointerException npe) {
                kms = null;
            }
        }

        // If the user didn't specify a SSLContext, use the default one
        if (context == null) {
            context = SSLContext.getInstance("TLS");
            context.init(kms, null, new java.security.SecureRandom());
        }
        Socket plain = socket;
        // Secure the plain connection
        socket = context.getSocketFactory().createSocket(plain,
                host, plain.getPort(), true);
        final SSLSocket sslSocket = (SSLSocket) socket;

        // Immediately set the enabled SSL protocols and ciphers. See SMACK-712 why this is
        // important (at least on certain platforms) and it seems to be a good idea anyways to
        // prevent an accidental implicit handshake.
        //TLSUtils.setEnabledProtocolsAndCiphers(sslSocket, config.getEnabledSSLProtocols(), config.getEnabledSSLCiphers());

        // Initialize the reader and writer with the new secured version
        initReaderAndWriter();
        sslSocket.startHandshake();

        final HostnameVerifier verifier = getConfiguration().getHostnameVerifier();
        if (verifier == null) {
            throw new IllegalStateException("No HostnameVerifier set. Use connectionConfiguration.setHostnameVerifier() to configure.");
        } else if (!verifier.verify(getServiceName(), sslSocket.getSession())) {
            throw new CertificateException("Hostname verification of certificate failed. Certificate does not authenticate " + getServiceName());
        }
        // Proceed to do the handshake
        // Set that TLS was successful
        usingTLS = true;
    }

    private XMPPInputOutputStream maybeGetCompressionHandler() {
        Compress.Feature compression = getFeature(Compress.Feature.ELEMENT, Compress.NAMESPACE);
        if (compression == null) {
            // Server does not support compression
            return null;
        }
        for (XMPPInputOutputStream handler : SmackConfiguration.getCompresionHandlers()) {
            String method = handler.getCompressionMethod();
            if (compression.getMethods().contains(method))
                return handler;
        }
        return null;
    }

    @Override
    public boolean isUsingCompression() {
        return compressionHandler != null && compressSyncPoint.wasSuccessful();
    }

    private void useCompression() throws NotConnectedException, NoResponseException, XMPPException {
        maybeCompressFeaturesReceived.checkIfSuccessOrWait();
        // If stream compression was offered by the server and we want to use
        // compression then send compression request to the server
        if ((compressionHandler = maybeGetCompressionHandler()) != null) {
            compressSyncPoint.sendAndWaitForResponseOrThrow(new Compress(compressionHandler.getCompressionMethod()));
        } else {
            LOGGER.warning("Could not enable compression because no matching handler/method pair was found");
        }
    }

    protected void connectInternal() throws HSSocketException, IOException{
        //TCP 연결을 맺고 reader와 writer를 설정한다. 만약 연결 설립중 에러가있다면 exception을 던진다.
        Log.d("HS","before connectUsingConfiguration");
        connectUsingConfiguration();
        Log.d("HS","after connectUsingConfiguration");
        //TCP port로 성공적으로 연결되었다.
        socketClosed = false;
        initConnection();
        Log.d("HS","after initConnection");
        // Wait with SASL auth until the SASL mechanisms have been received
        saslFeatureReceived.checkIfSuccessOrWaitOrThrow();

        // If TLS is required but the server doesn't offer it, disconnect
        // from the server and throw an error. First check if we've already negotiated TLS
        // and are secure, however (features get parsed a second time after TLS is established).
        if (!isSecureConnection() && getConfiguration().getSecurityMode() == SecurityMode.required) {
            shutdown();
            throw new SecurityRequiredByClientException();
        }

        // Make note of the fact that we're now connected.
        connected = true;
        callConnectionConnectedListener();

        // Automatically makes the login if the user was previously connected successfully
        // to the server and the connection was terminated abruptly
        if (wasAuthenticated) {
            login();
            notifyReconnection();
        }
    }

    /**
     * Sends out a notification that there was an error with the connection
     * and closes the connection. Also prints the stack trace of the given exception
     *
     * @param e the exception that causes the connection close event.
     */
    private synchronized void notifyConnectionError(Exception e) {
        // Listeners were already notified of the exception, return right here.
        if ((packetReader == null || packetReader.done) &&
                (packetWriter == null || packetWriter.done())) return;

        // Closes the connection temporary. A reconnection is possible
        instantShutdown();

        // Notify connection listeners of the error.
        callConnectionClosedOnErrorListener(e);
    }

    /**
     * For unit testing purposes
     *
     * @param writer
     */
    protected void setWriter(Writer writer) {
        this.writer = writer;
    }

    protected void afterFeaturesReceived() throws SmackException.NotConnectedException {
        StartTls startTlsFeature = getFeature(StartTls.ELEMENT, StartTls.NAMESPACE);
        if (startTlsFeature != null) {
            if (startTlsFeature.required() && config.getSecurityMode() == SecurityMode.disabled) {
                notifyConnectionError(new SecurityRequiredByServerException());
                return;
            }
            if (config.getSecurityMode() != ConnectionConfiguration.SecurityMode.disabled) {
                send(new StartTls());
            }
        }

        if (getSASLAuthentication().authenticationSuccessful()) {
            // If we have received features after the SASL has been successfully completed, then we
            // have also *maybe* received, as it is an optional feature, the compression feature
            // from the server.
            maybeCompressFeaturesReceived.reportSuccess();
        }
    }
    protected Lock getConnectionLock() {
        return connectionLock;
    }
    public String getServiceName() {
        if (serviceName != null) {
            return serviceName;
        }
        return config.getServiceName();
    }
    public String getStreamId() {
        if (!isConnected()) {
            return null;
        }
        return streamId;
    }
    public long getPacketReplyTimeout() {
        return packetReplyTimeout;
    }
    void openStream() throws HSSocketException {
        CharSequence to = getServiceName();
        CharSequence from = null;
        CharSequence localpart = config.getUsername();
        if (localpart != null) {
            from = XMPPStringUtils.completeJidFrom(localpart, to);
        }
        String id = getStreamId();
        send(new StreamOpen(to, from, id));
        try {
            packetReader.parser = PacketParserUtils.newXmppParser(reader);
        }
        catch (XmlPullParserException e) {
            throw new HSSocketException(e);
        }
    }

    protected class PacketReader {
        XmlPullParser parser;
        private volatile boolean done;

        void init() {
            done = false;
            HSTask<Void,Void,Void> receiveTask=new HSTask<Void,Void,Void>(){
                @Override
                protected Void doInBackground(Void ... arg){
                    parsePackets();
                    return null;
                }
            };
            receiveTask.execute();
        }

        void shutdown() {
            done = true;
        }

        private void parsePackets() {
            try {
                initalOpenStreamSend.checkIfSuccessOrWait();
                int eventType = parser.getEventType();
                while (!done) {
                    Log.d("HS","parser.getName()");
                    Log.d("HS","엉엉"+parser.getName());
                    switch (eventType) {
                        case XmlPullParser.START_TAG:
                            final String name = parser.getName();
                            switch (name) {
                                case Message.ELEMENT:
                                case IQ.IQ_ELEMENT:
                                case Presence.ELEMENT:
                                    try {
                                        parseAndProcessStanza(parser);
                                    } finally {
                                        clientHandledStanzasCount = SMUtils.incrementHeight(clientHandledStanzasCount);
                                    }
                                    break;
                                case "stream":
                                    // We found an opening stream.
                                    if ("jabber:client".equals(parser.getNamespace(null))) {
                                        streamId = parser.getAttributeValue("", "id");
                                        String reportedServiceName = parser.getAttributeValue("", "from");
                                        assert(reportedServiceName.equals(config.getServiceName()));
                                    }
                                    break;
                                case "error":
                                    throw new StreamErrorException(PacketParserUtils.parseStreamError(parser));
                                case "features":
                                    parseFeatures(parser);
                                    break;
                                case "proceed":
                                    Log.d("HS","take proceed!!");
                                    try {
                                        // Secure the connection by negotiating TLS
                                        proceedTLSReceived();
                                        // Send a new opening stream to the server
                                        openStream();
                                    }
                                    catch (Exception e) {
                                        // We report any failure regarding TLS in the second stage of XMPP
                                        // connection establishment, namely the SASL authentication
                                        saslFeatureReceived.reportFailure(new SmackException(e));
                                        throw e;
                                    }
                                    break;
                                case "failure":
                                    String namespace = parser.getNamespace(null);
                                    switch (namespace) {
                                        case "urn:ietf:params:xml:ns:xmpp-tls":
                                            // TLS negotiation has failed. The server will close the connection
                                            // TODO Parse failure stanza
                                            throw new XMPPErrorException("TLS negotiation has failed", null);
                                        case "http://jabber.org/protocol/compress":
                                            // Stream compression has been denied. This is a recoverable
                                            // situation. It is still possible to authenticate and
                                            // use the connection but using an uncompressed connection
                                            // TODO Parse failure stanza
                                            compressSyncPoint.reportFailure(new XMPPErrorException(
                                                    "Could not establish compression", null));
                                            break;
                                        case SaslStreamElements.NAMESPACE:
                                            // SASL authentication has failed. The server may close the connection
                                            // depending on the number of retries
                                            final SASLFailure failure = PacketParserUtils.parseSASLFailure(parser);
                                            getSASLAuthentication().authenticationFailed(failure);
                                            break;
                                    }
                                    break;
                                case Challenge.ELEMENT:
                                    // The server is challenging the SASL authentication made by the client
                                    String challengeData = parser.nextText();
                                    Log.d("HSTest","ChallengeData");
                                    Log.d("HSTest",challengeData);
                                    getSASLAuthentication().challengeReceived(challengeData);
                                    break;
                                case Success.ELEMENT:
                                    Success success = new SaslStreamElements.Success(parser.nextText());
                                    // We now need to bind a resource for the connection
                                    // Open a new stream and wait for the response
                                    openStream();
                                    // The SASL authentication with the server was successful. The next step
                                    // will be to bind the resource
                                    getSASLAuthentication().authenticated(success);
                                    break;
                                case Compressed.ELEMENT:
                                    // Server confirmed that it's possible to use stream compression. Start
                                    // stream compression
                                    // Initialize the reader and writer with the new compressed version
                                    initReaderAndWriter();
                                    // Send a new opening stream to the server
                                    openStream();
                                    // Notify that compression is being used
                                    compressSyncPoint.reportSuccess();
                                    break;
                                case Enabled.ELEMENT:
                                    Enabled enabled = ParseStreamManagement.enabled(parser);
                                    if (enabled.isResumeSet()) {
                                        smSessionId = enabled.getId();
                                        if (StringUtils.isNullOrEmpty(smSessionId)) {
                                            XMPPErrorException xmppException = new XMPPErrorException(
                                                    "Stream Management 'enabled' element with resume attribute but without session id received",
                                                    new XMPPError(
                                                            XMPPError.Condition.bad_request));
                                            smEnabledSyncPoint.reportFailure(xmppException);
                                            throw xmppException;
                                        }
                                        smServerMaxResumptimTime = enabled.getMaxResumptionTime();
                                    } else {
                                        // Mark this a non-resumable stream by setting smSessionId to null
                                        smSessionId = null;
                                    }
                                    clientHandledStanzasCount = 0;
                                    smWasEnabledAtLeastOnce = true;
                                    smEnabledSyncPoint.reportSuccess();
                                    LOGGER.fine("Stream Management (XEP-198): succesfully enabled");
                                    break;
                                case Failed.ELEMENT:
                                    Failed failed = ParseStreamManagement.failed(parser);
                                    XMPPError xmppError = new XMPPError(failed.getXMPPErrorCondition());
                                    XMPPException xmppException = new XMPPErrorException("Stream Management failed", xmppError);
                                    // If only XEP-198 would specify different failure elements for the SM
                                    // enable and SM resume failure case. But this is not the case, so we
                                    // need to determine if this is a 'Failed' response for either 'Enable'
                                    // or 'Resume'.
                                    if (smResumedSyncPoint.requestSent()) {
                                        smResumedSyncPoint.reportFailure(xmppException);
                                    }
                                    else {
                                        if (!smEnabledSyncPoint.requestSent()) {
                                            throw new IllegalStateException("Failed element received but SM was not previously enabled");
                                        }
                                        smEnabledSyncPoint.reportFailure(xmppException);
                                        // Report success for last lastFeaturesReceived so that in case a
                                        // failed resumption, we can continue with normal resource binding.
                                        // See text of XEP-198 5. below Example 11.
                                        lastFeaturesReceived.reportSuccess();
                                    }
                                    break;
                                case Resumed.ELEMENT:
                                    Resumed resumed = ParseStreamManagement.resumed(parser);
                                    if (!smSessionId.equals(resumed.getPrevId())) {
                                        throw new StreamIdDoesNotMatchException(smSessionId, resumed.getPrevId());
                                    }
                                    // Mark SM as enabled and resumption as successful.
                                    smResumedSyncPoint.reportSuccess();
                                    smEnabledSyncPoint.reportSuccess();
                                    // First, drop the stanzas already handled by the server
                                    processHandledCount(resumed.getHandledCount());
                                    // Then re-send what is left in the unacknowledged queue
                                    List<Stanza> stanzasToResend = new ArrayList<>(unacknowledgedStanzas.size());
                                    unacknowledgedStanzas.drainTo(stanzasToResend);
                                    for (Stanza stanza : stanzasToResend) {
                                        sendStanzaInternal(stanza);
                                    }
                                    // If there where stanzas resent, then request a SM ack for them.
                                    // Writer's sendStreamElement() won't do it automatically based on
                                    // predicates.
                                    if (!stanzasToResend.isEmpty()) {
                                        requestSmAcknowledgementInternal();
                                    }
                                    LOGGER.fine("Stream Management (XEP-198): Stream resumed");
                                    break;
                                case AckAnswer.ELEMENT:
                                    AckAnswer ackAnswer = ParseStreamManagement.ackAnswer(parser);
                                    processHandledCount(ackAnswer.getHandledCount());
                                    break;
                                case AckRequest.ELEMENT:
                                    ParseStreamManagement.ackRequest(parser);
                                    if (smEnabledSyncPoint.wasSuccessful()) {
                                        sendSmAcknowledgementInternal();
                                    } else {
                                        LOGGER.warning("SM Ack Request received while SM is not enabled");
                                    }
                                    break;
                                default:
                                    LOGGER.warning("Unknown top level stream element: " + name);
                                    break;
                            }
                            break;
                        case XmlPullParser.END_TAG:
                            if (parser.getName().equals("stream")) {
                                // Disconnect the connection
                                disconnect();
                            }
                            break;
                        case XmlPullParser.END_DOCUMENT:
                            // END_DOCUMENT only happens in an error case, as otherwise we would see a
                            // closing stream element before.
                            throw new SmackException(
                                    "Parser got END_DOCUMENT event. This could happen e.g. if the server closed the connection without sending a closing stream element");
                    }
                    eventType = parser.next();
                }
            }
            catch (Exception e) {
                // The exception can be ignored if the the connection is 'done'
                // or if the it was caused because the socket got closed
                if (!(done || isSocketClosed())) {
                    // Close the connection and notify connection listeners of the
                    // error.
                    notifyConnectionError(e);
                }
            }
        }
    }

    protected class PacketWriter {
        public static final int QUEUE_SIZE = HSXMPPTCPConnection.QUEUE_SIZE;

        private final ArrayBlockingQueueWithShutdown<Element> queue = new ArrayBlockingQueueWithShutdown<Element>(
                QUEUE_SIZE, true);

        protected SynchronizationPoint<NoResponseException> shutdownDone = new SynchronizationPoint<NoResponseException>(
                HSXMPPTCPConnection.this);

        protected volatile Long shutdownTimestamp = null;

        private volatile boolean instantShutdown;

        private boolean shouldBundleAndDefer;
        private class WriterTask extends HSTask<Void,Void,Void> {
            @Override
            protected Void doInBackground(Void... ignore) {
                writePackets();
                return null;
            }
        }
        void init() {
            shutdownDone.init();
            shutdownTimestamp = null;
            if (unacknowledgedStanzas != null) {
                drainWriterQueueToUnacknowledgedStanzas();
            }
            queue.start();
            //쓰레드 이름 "HS Packet Writer (" + getConnectionCounter() + ")" 으로 설정 할 예정.
            HSTask writerTask=new WriterTask();
            writerTask.execute();
        }

        private boolean done() {
            return shutdownTimestamp != null;
        }

        protected void throwNotConnectedExceptionIfDoneAndResumptionNotPossible() throws NotConnectedException {
            if (done() && !isSmResumptionPossible()) {
                throw new HSSocketException.NotConnectedException();
            }
        }

        protected void sendStreamElement(Element element) throws NotConnectedException {
            throwNotConnectedExceptionIfDoneAndResumptionNotPossible();

            boolean enqueued = false;
            while (!enqueued) {
                try {
                    queue.put(element);
                    enqueued = true;
                }
                catch (InterruptedException e) {
                    throwNotConnectedExceptionIfDoneAndResumptionNotPossible();
                    // If the method above did not throw, then the sending thread was interrupted
                    // TODO in a later version of Smack the InterruptedException should be thrown to
                    // allow users to interrupt a sending thread that is currently blocking because
                    // the queue is full.
                    LOGGER.log(Level.WARNING, "Sending thread was interrupted", e);
                }
            }
        }

        /**
         * Shuts down the stanza(/packet) writer. Once this method has been called, no further
         * packets will be written to the server.
         */
        void shutdown(boolean instant) {
            instantShutdown = instant;
            shutdownTimestamp = System.currentTimeMillis();
            queue.shutdown();
            try {
                shutdownDone.checkIfSuccessOrWait();
            }
            catch (NoResponseException e) {
                LOGGER.log(Level.WARNING, "shutdownDone was not marked as successful by the writer thread", e);
            }
        }

        //queue에서 대기중인 Element를 하나 꺼내온다.
        private Element nextStreamElement() {
            //queue가 비워지기전에 이미 비워져있는지 체크한다.
            if (queue.isEmpty()) {
                shouldBundleAndDefer = true;
            }
            Element packet = null;
            try {
                packet = queue.take();
            }
            catch (InterruptedException e) {
                if (!queue.isShutdown()) {
                    // Users shouldn't try to interrupt the packet writer thread
                    LOGGER.log(Level.WARNING, "Packet writer thread was interrupted. Don't do that. Use disconnect() instead.", e);
                }
            }
            return packet;
        }
        private void drainWriterQueueToUnacknowledgedStanzas() {
            List<Element> elements = new ArrayList<Element>(queue.size());
            queue.drainTo(elements);
            for (Element element : elements) {
                if (element instanceof Stanza) {
                    unacknowledgedStanzas.add((Stanza) element);
                }
            }
        }
        private void writePackets() {
            try {
                openStream();
                initalOpenStreamSend.reportSuccess();
                //queue로부터 패킷을 꺼내어 전송한다.
                while (!done()) {
                    Element element = nextStreamElement();
                    if (element == null) {
                        continue;
                    }

                    // Get a local version of the bundle and defer callback, in case it's unset
                    // between the null check and the method invocation
                    final BundleAndDeferCallback localBundleAndDeferCallback = bundleAndDeferCallback;
                    // If the preconditions are given (e.g. bundleAndDefer callback is set, queue is
                    // empty), then we could wait a bit for further stanzas attempting to decrease
                    // our energy consumption
                    if (localBundleAndDeferCallback != null && isAuthenticated() && shouldBundleAndDefer) {
                        // Reset shouldBundleAndDefer to false, nextStreamElement() will set it to true once the
                        // queue is empty again.
                        shouldBundleAndDefer = false;
                        final AtomicBoolean bundlingAndDeferringStopped = new AtomicBoolean();
                        final int bundleAndDeferMillis = localBundleAndDeferCallback.getBundleAndDeferMillis(new BundleAndDefer(
                                bundlingAndDeferringStopped));
                        if (bundleAndDeferMillis > 0) {
                            long remainingWait = bundleAndDeferMillis;
                            final long waitStart = System.currentTimeMillis();
                            synchronized (bundlingAndDeferringStopped) {
                                while (!bundlingAndDeferringStopped.get() && remainingWait > 0) {
                                    bundlingAndDeferringStopped.wait(remainingWait);
                                    remainingWait = bundleAndDeferMillis
                                            - (System.currentTimeMillis() - waitStart);
                                }
                            }
                        }
                    }

                    Stanza packet = null;
                    if (element instanceof Stanza) {
                        packet = (Stanza) element;
                    }
                    else if (element instanceof Enable) {
                        // The client needs to add messages to the unacknowledged stanzas queue
                        // right after it sent 'enabled'. Stanza will be added once
                        // unacknowledgedStanzas is not null.
                        unacknowledgedStanzas = new ArrayBlockingQueue<>(QUEUE_SIZE);
                    }
                    // Check if the stream element should be put to the unacknowledgedStanza
                    // queue. Note that we can not do the put() in sendStanzaInternal() and the
                    // packet order is not stable at this point (sendStanzaInternal() can be
                    // called concurrently).
                    if (unacknowledgedStanzas != null && packet != null) {
                        // If the unacknowledgedStanza queue is nearly full, request an new ack
                        // from the server in order to drain it
                        if (unacknowledgedStanzas.size() == 0.8 * HSXMPPTCPConnection.QUEUE_SIZE) {
                            Log.d("HS","AckRequest.INSTANCE.toXML().toString()");
                            Log.d("HS",AckRequest.INSTANCE.toXML().toString());
                            writer.write(AckRequest.INSTANCE.toXML().toString());
                            writer.flush();
                        }
                        try {
                            // It is important the we put the stanza in the unacknowledged stanza
                            // queue before we put it on the wire
                            unacknowledgedStanzas.put(packet);
                        }
                        catch (InterruptedException e) {
                            throw new IllegalStateException(e);
                        }
                    }
                    Log.d("HS","element.INSTANCE.toXML().toString()");
                    Log.d("HS",element.toXML().toString());
                    writer.write(element.toXML().toString());
                    if (queue.isEmpty()) {
                        writer.flush();
                    }
                    if (packet != null) {
                        firePacketSendingListeners(packet);
                    }
                }
                if (!instantShutdown) {
                    // Flush out the rest of the queue.
                    try {
                        while (!queue.isEmpty()) {
                            Element packet = queue.remove();
                            writer.write(packet.toXML().toString());
                        }
                        writer.flush();
                    }
                    catch (Exception e) {
                        LOGGER.log(Level.WARNING,
                                "Exception flushing queue during shutdown, ignore and continue",
                                e);
                    }

                    // Close the stream.
                    try {
                        writer.write("</stream:stream>");
                        writer.flush();
                    }
                    catch (Exception e) {
                        LOGGER.log(Level.WARNING, "Exception writing closing stream element", e);
                    }
                    // Delete the queue contents (hopefully nothing is left).
                    queue.clear();
                } else if (instantShutdown && isSmEnabled()) {
                    // This was an instantShutdown and SM is enabled, drain all remaining stanzas
                    // into the unacknowledgedStanzas queue
                    drainWriterQueueToUnacknowledgedStanzas();
                }

                try {
                    writer.close();
                }
                catch (Exception e) {
                    // Do nothing
                }
            }
            catch (Exception e) {
                // The exception can be ignored if the the connection is 'done'
                // or if the it was caused because the socket got closed
                if (!(done() || isSocketClosed())) {
                    notifyConnectionError(e);
                } else {
                    LOGGER.log(Level.FINE, "Ignoring Exception in writePackets()", e);
                }
            } finally {
                LOGGER.fine("Reporting shutdownDone success in writer thread");
                shutdownDone.reportSuccess();
            }
        }
    }

    /**
     * Set if Stream Management should be used by default for new connections.
     *
     * @param useSmDefault true to use Stream Management for new connections.
     */
    public static void setUseStreamManagementDefault(boolean useSmDefault) {
        HSXMPPTCPConnection.useSmDefault = useSmDefault;
    }

    /**
     * Set if Stream Management resumption should be used by default for new connections.
     *
     * @param useSmResumptionDefault true to use Stream Management resumption for new connections.
     * @deprecated use {@link #setUseStreamManagementResumptionDefault(boolean)} instead.
     */
    @Deprecated
    public static void setUseStreamManagementResumptiodDefault(boolean useSmResumptionDefault) {
        setUseStreamManagementResumptionDefault(useSmResumptionDefault);
    }

    /**
     * Set if Stream Management resumption should be used by default for new connections.
     *
     * @param useSmResumptionDefault true to use Stream Management resumption for new connections.
     */
    public static void setUseStreamManagementResumptionDefault(boolean useSmResumptionDefault) {
        if (useSmResumptionDefault) {
            // Also enable SM is resumption is enabled
            setUseStreamManagementDefault(useSmResumptionDefault);
        }
        HSXMPPTCPConnection.useSmResumptionDefault = useSmResumptionDefault;
    }

    /**
     * Set if Stream Management should be used if supported by the server.
     *
     * @param useSm true to use Stream Management.
     */
    public void setUseStreamManagement(boolean useSm) {
        this.useSm = useSm;
    }

    /**
     * Set if Stream Management resumption should be used if supported by the server.
     *
     * @param useSmResumption true to use Stream Management resumption.
     */
    public void setUseStreamManagementResumption(boolean useSmResumption) {
        if (useSmResumption) {
            // Also enable SM is resumption is enabled
            setUseStreamManagement(useSmResumption);
        }
        this.useSmResumption = useSmResumption;
    }

    /**
     * Set the preferred resumption time in seconds.
     * @param resumptionTime the preferred resumption time in seconds
     */
    public void setPreferredResumptionTime(int resumptionTime) {
        smClientMaxResumptionTime = resumptionTime;
    }

    /**
     * Add a predicate for Stream Management acknowledgment requests.
     * <p>
     * Those predicates are used to determine when a Stream Management acknowledgement request is send to the server.
     * Some pre-defined predicates are found in the <code>org.jivesoftware.smack.sm.predicates</code> package.
     * </p>
     * <p>
     * If not predicate is configured, the {@link Predicate#forMessagesOrAfter5Stanzas()} will be used.
     * </p>
     *
     * @param predicate the predicate to add.
     * @return if the predicate was not already active.
     */
    public boolean addRequestAckPredicate(StanzaFilter predicate) {
        synchronized (requestAckPredicates) {
            return requestAckPredicates.add(predicate);
        }
    }

    /**
     * Remove the given predicate for Stream Management acknowledgment request.
     * @param predicate the predicate to remove.
     * @return true if the predicate was removed.
     */
    public boolean removeRequestAckPredicate(StanzaFilter predicate) {
        synchronized (requestAckPredicates) {
            return requestAckPredicates.remove(predicate);
        }
    }

    /**
     * Remove all predicates for Stream Management acknowledgment requests.
     */
    public void removeAllRequestAckPredicates() {
        synchronized (requestAckPredicates) {
            requestAckPredicates.clear();
        }
    }

    /**
     * Send an unconditional Stream Management acknowledgement request to the server.
     *
     * @throws StreamManagementNotEnabledException if Stream Mangement is not enabled.
     * @throws NotConnectedException if the connection is not connected.
     */
    public void requestSmAcknowledgement() throws StreamManagementNotEnabledException, NotConnectedException {
        if (!isSmEnabled()) {
            throw new StreamManagementNotEnabledException();
        }
        requestSmAcknowledgementInternal();
    }

    private void requestSmAcknowledgementInternal() throws SmackException.NotConnectedException {
        packetWriter.sendStreamElement(AckRequest.INSTANCE);
    }

    /**
     * Send a unconditional Stream Management acknowledgment to the server.
     * <p>
     * See <a href="http://xmpp.org/extensions/xep-0198.html#acking">XEP-198: Stream Management § 4. Acks</a>:
     * "Either party MAY send an <a/> element at any time (e.g., after it has received a certain number of stanzas,
     * or after a certain period of time), even if it has not received an <r/> element from the other party."
     * </p>
     *
     * @throws StreamManagementNotEnabledException if Stream Management is not enabled.
     * @throws NotConnectedException if the connection is not connected.
     */
    public void sendSmAcknowledgement() throws StreamManagementNotEnabledException, NotConnectedException {
        if (!isSmEnabled()) {
            throw new StreamManagementNotEnabledException();
        }
        sendSmAcknowledgementInternal();
    }

    private void sendSmAcknowledgementInternal() throws SmackException.NotConnectedException {
        packetWriter.sendStreamElement(new AckAnswer(clientHandledStanzasCount));
    }

    /**
     * Add a Stanza acknowledged listener.
     * <p>
     * Those listeners will be invoked every time a Stanza has been acknowledged by the server. The will not get
     * automatically removed. Consider using {@link #addStanzaIdAcknowledgedListener(String, StanzaListener)} when
     * possible.
     * </p>
     *
     * @param listener the listener to add.
     */
    public void addStanzaAcknowledgedListener(StanzaListener listener) {
        stanzaAcknowledgedListeners.add(listener);
    }

    /**
     * Remove the given Stanza acknowledged listener.
     *
     * @param listener the listener.
     * @return true if the listener was removed.
     */
    public boolean removeStanzaAcknowledgedListener(StanzaListener listener) {
        return stanzaAcknowledgedListeners.remove(listener);
    }

    /**
     * Remove all stanza acknowledged listeners.
     */
    public void removeAllStanzaAcknowledgedListeners() {
        stanzaAcknowledgedListeners.clear();
    }

    /**
     * Add a new Stanza ID acknowledged listener for the given ID.
     * <p>
     * The listener will be invoked if the stanza with the given ID was acknowledged by the server. It will
     * automatically be removed after the listener was run.
     * </p>
     *
     * @param id the stanza ID.
     * @param listener the listener to invoke.
     * @return the previous listener for this stanza ID or null.
     * @throws StreamManagementNotEnabledException if Stream Management is not enabled.
     */
    public StanzaListener addStanzaIdAcknowledgedListener(final String id, StanzaListener listener) throws StreamManagementNotEnabledException {
        // Prevent users from adding callbacks that will never get removed
        if (!smWasEnabledAtLeastOnce) {
            throw new StreamManagementNotEnabledException();
        }
        // Remove the listener after max. 12 hours
        final int removeAfterSeconds = Math.min(getMaxSmResumptionTime(), 12 * 60 * 60);
        schedule(new Runnable() {
            @Override
            public void run() {
                stanzaIdAcknowledgedListeners.remove(id);
            }
        }, removeAfterSeconds, TimeUnit.SECONDS);
        return stanzaIdAcknowledgedListeners.put(id, listener);
    }

    /**
     * Remove the Stanza ID acknowledged listener for the given ID.
     *
     * @param id the stanza ID.
     * @return true if the listener was found and removed, false otherwise.
     */
    public StanzaListener removeStanzaIdAcknowledgedListener(String id) {
        return stanzaIdAcknowledgedListeners.remove(id);
    }

    /**
     * Removes all Stanza ID acknowledged listeners.
     */
    public void removeAllStanzaIdAcknowledgedListeners() {
        stanzaIdAcknowledgedListeners.clear();
    }

    /**
     * Returns true if Stream Management is supported by the server.
     *
     * @return true if Stream Management is supported by the server.
     */
    public boolean isSmAvailable() {
        return hasFeature(StreamManagementFeature.ELEMENT, StreamManagement.NAMESPACE);
    }

    /**
     * Returns true if Stream Management was successfully negotiated with the server.
     *
     * @return true if Stream Management was negotiated.
     */
    public boolean isSmEnabled() {
        return smEnabledSyncPoint.wasSuccessful();
    }

    /**
     * Returns true if the stream was successfully resumed with help of Stream Management.
     *
     * @return true if the stream was resumed.
     */
    public boolean streamWasResumed() {
        return smResumedSyncPoint.wasSuccessful();
    }

    /**
     * Returns true if the connection is disconnected by a Stream resumption via Stream Management is possible.
     *
     * @return true if disconnected but resumption possible.
     */
    public boolean isDisconnectedButSmResumptionPossible() {
        return disconnectedButResumeable && isSmResumptionPossible();
    }
    //스트림이 재개 가능한지 체크(timeout을 이용)
    public boolean isSmResumptionPossible() {
        if (smSessionId == null)
            return false;

        final Long shutdownTimestamp = packetWriter.shutdownTimestamp;
        // Seems like we are already reconnected, report true
        if (shutdownTimestamp == null) {
            return true;
        }

        // See if resumption time is over
        long current = System.currentTimeMillis();
        long maxResumptionMillies = ((long) getMaxSmResumptionTime()) * 1000;
        if (current > shutdownTimestamp + maxResumptionMillies) {
            // Stream resumption is *not* possible if the current timestamp is greater then the greatest timestamp where
            // resumption is possible
            return false;
        } else {
            return true;
        }
    }

    private void dropSmState() {
        // clientHandledCount and serverHandledCount will be reset on <enable/> and <enabled/>
        // respective. No need to reset them here.
        smSessionId = null;
        unacknowledgedStanzas = null;
    }

    public int getMaxSmResumptionTime() {
        int clientResumptionTime = smClientMaxResumptionTime > 0 ? smClientMaxResumptionTime : Integer.MAX_VALUE;
        int serverResumptionTime = smServerMaxResumptimTime > 0 ? smServerMaxResumptimTime : Integer.MAX_VALUE;
        return Math.min(clientResumptionTime, serverResumptionTime);
    }

    private void processHandledCount(long handledCount) throws StreamManagementCounterError {
        long ackedStanzasCount = SMUtils.calculateDelta(handledCount, serverHandledStanzasCount);
        final List<Stanza> ackedStanzas = new ArrayList<Stanza>(
                ackedStanzasCount <= Integer.MAX_VALUE ? (int) ackedStanzasCount
                        : Integer.MAX_VALUE);
        for (long i = 0; i < ackedStanzasCount; i++) {
            Stanza ackedStanza = unacknowledgedStanzas.poll();
            // If the server ack'ed a stanza, then it must be in the
            // unacknowledged stanza queue. There can be no exception.
            if (ackedStanza == null) {
                throw new StreamManagementCounterError(handledCount, serverHandledStanzasCount,
                        ackedStanzasCount, ackedStanzas);
            }
            ackedStanzas.add(ackedStanza);
        }

        boolean atLeastOneStanzaAcknowledgedListener = false;
        if (!stanzaAcknowledgedListeners.isEmpty()) {
            // If stanzaAcknowledgedListeners is not empty, the we have at least one
            atLeastOneStanzaAcknowledgedListener = true;
        }
        else {
            // Otherwise we look for a matching id in the stanza *id* acknowledged listeners
            for (Stanza ackedStanza : ackedStanzas) {
                String id = ackedStanza.getStanzaId();
                if (id != null && stanzaIdAcknowledgedListeners.containsKey(id)) {
                    atLeastOneStanzaAcknowledgedListener = true;
                    break;
                }
            }
        }

        // Only spawn a new thread if there is a chance that some listener is invoked
        if (atLeastOneStanzaAcknowledgedListener) {
            asyncGo(new Runnable() {
                @Override
                public void run() {
                    for (Stanza ackedStanza : ackedStanzas) {
                        for (StanzaListener listener : stanzaAcknowledgedListeners) {
                            try {
                                listener.processPacket(ackedStanza);
                            }
                            catch (SmackException.NotConnectedException e) {
                                LOGGER.log(Level.FINER, "Received not connected exception", e);
                            }
                        }
                        String id = ackedStanza.getStanzaId();
                        if (StringUtils.isNullOrEmpty(id)) {
                            continue;
                        }
                        StanzaListener listener = stanzaIdAcknowledgedListeners.remove(id);
                        if (listener != null) {
                            try {
                                listener.processPacket(ackedStanza);
                            }
                            catch (SmackException.NotConnectedException e) {
                                LOGGER.log(Level.FINER, "Received not connected exception", e);
                            }
                        }
                    }
                }
            });
        }

        serverHandledStanzasCount = handledCount;
    }

    /**
     * Set the default bundle and defer callback used for new connections.
     *
     * @param defaultBundleAndDeferCallback
     * @see BundleAndDeferCallback
     * @since 4.1
     */
    public static void setDefaultBundleAndDeferCallback(BundleAndDeferCallback defaultBundleAndDeferCallback) {
        HSXMPPTCPConnection.defaultBundleAndDeferCallback = defaultBundleAndDeferCallback;
    }

    /**
     * Set the bundle and defer callback used for this connection.
     * <p>
     * You can use <code>null</code> as argument to reset the callback. Outgoing stanzas will then
     * no longer get deferred.
     * </p>
     *
     * @param bundleAndDeferCallback the callback or <code>null</code>.
     * @see BundleAndDeferCallback
     * @since 4.1
     */
    public void setBundleandDeferCallback(BundleAndDeferCallback bundleAndDeferCallback) {
        this.bundleAndDeferCallback = bundleAndDeferCallback;
    }

}
