package socket.xmpp.sasl;

import org.jivesoftware.smack.util.StringTransformer;

import HS.string.StringUtils;
import HS.stringEncoder.Base64;
import socket.xmpp.HSXMPPTCPConnection;
import socket.HSSocketException;
import socket.HSSocketException.NotConnectedException;

public abstract class SASLMechanism implements Comparable<SASLMechanism> {
    public static final String CRAMMD5 = "CRAM-MD5";
    public static final String DIGESTMD5 = "DIGEST-MD5";
    public static final String EXTERNAL = "EXTERNAL";
    public static final String GSSAPI = "GSSAPI";
    public static final String PLAIN = "PLAIN";
    // TODO Remove once Smack's min Android API is 9, where java.text.Normalizer is available
    private static StringTransformer saslPrepTransformer;

    public static void setSaslPrepTransformer(StringTransformer stringTransformer) {
        saslPrepTransformer = stringTransformer;
    }

    protected HSXMPPTCPConnection connection;

    protected String authenticationId;

    /**
     * The name of the XMPP service
     */
    protected String serviceName;

    /**
     * The users password
     */
    protected String password;
    protected String host;

    public final void authenticate(String username, String host, String serviceName, String password)
            throws HSSocketException, NotConnectedException {
        this.authenticationId = username;
        this.host = host;
        this.serviceName = serviceName;
        this.password = password;
        authenticateInternal();
        authenticate();
    }

    protected void authenticateInternal() throws HSSocketException {
    }
    public void authenticate(String host,String serviceName, CallbackHandler cbh)
            throws HSSocketException, NotConnectedException {
        this.host = host;
        this.serviceName = serviceName;
        authenticateInternal(cbh);
        authenticate();
    }

    protected abstract void authenticateInternal(CallbackHandler cbh) throws HSSocketException;

    private final void authenticate() throws HSSocketException, NotConnectedException {
        byte[] authenticationBytes = getAuthenticationText();
        String authenticationText;
        // Some SASL mechanisms do return an empty array (e.g. EXTERNAL from javax), so check that
        // the array is not-empty. Mechanisms are allowed to return either 'null' or an empty array
        // if there is no authentication text.
        if (authenticationBytes != null && authenticationBytes.length > 0) {
            authenticationText = Base64.encodeToString(authenticationBytes);
        } else {
            // RFC6120 6.4.2 "If the initiating entity needs to send a zero-length initial response,
            // it MUST transmit the response as a single equals sign character ("="), which
            // indicates that the response is present but contains no data."
            authenticationText = "=";
        }
        // Send the authentication to the server
        connection.send(new AuthMechanism(getName(), authenticationText));
    }

    protected abstract byte[] getAuthenticationText() throws HSSocketException;

    public final void challengeReceived(String challengeString, boolean finalChallenge) throws HSSocketException, NotConnectedException {
        byte[] challenge = Base64.decode(challengeString);
        byte[] response = evaluateChallenge(challenge);
        if (finalChallenge) {
            return;
        }

        Response responseStanza;
        if (response == null) {
            responseStanza = new Response();
        }
        else {
            responseStanza = new Response(Base64.encodeToString(response));
        }

        // Send the authentication to the server
        connection.send(responseStanza);
    }

    protected byte[] evaluateChallenge(byte[] challenge) throws HSSocketException {
        return null;
    }

    public final int compareTo(SASLMechanism other) {
        return getPriority() - other.getPriority();
    }
    public abstract String getName();
    public abstract int getPriority();

    public abstract void checkIfSuccessfulOrThrow() throws HSSocketException;

    public SASLMechanism instanceForAuthentication(HSXMPPTCPConnection connection) {
        SASLMechanism saslMechansim = newInstance();
        saslMechansim.connection = connection;
        return saslMechansim;
    }

    protected abstract SASLMechanism newInstance();

    protected static byte[] toBytes(String string) {
        return StringUtils.toBytes(string);
    }
    protected static String saslPrep(String string) {
        StringTransformer stringTransformer = saslPrepTransformer;
        if (stringTransformer != null) {
            return stringTransformer.transform(string);
        }
        return string;
    }
}
