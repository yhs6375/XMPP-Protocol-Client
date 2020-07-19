package socket.xmpp.sasl;

import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.sasl.SASLErrorException;
import org.jivesoftware.smack.sasl.SASLMechanism;
import org.jivesoftware.smack.tcp.XMPPTCPConnection;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import javax.security.auth.callback.CallbackHandler;

import socket.xmpp.HSXMPPTCPConnection;

public class SASLAuthentication {
    private static final Logger LOGGER = Logger.getLogger(SASLAuthentication.class.getName());
    private static final List<SASLMechanism> REGISTERED_MECHANISMS = new ArrayList<SASLMechanism>();
    private static final Set<String> BLACKLISTED_MECHANISMS = new HashSet<String>();
    public static void registerSASLMechanism(SASLMechanism mechanism) {
        synchronized (REGISTERED_MECHANISMS) {
            REGISTERED_MECHANISMS.add(mechanism);
            Collections.sort(REGISTERED_MECHANISMS);
        }
    }
    public static Map<String, String> getRegisterdSASLMechanisms() {
        Map<String, String> answer = new HashMap<String, String>();
        synchronized (REGISTERED_MECHANISMS) {
            for (SASLMechanism mechanism : REGISTERED_MECHANISMS) {
                answer.put(mechanism.getClass().getName(), mechanism.getName());
            }
        }
        return answer;
    }
    public static boolean unregisterSASLMechanism(String clazz) {
        synchronized (REGISTERED_MECHANISMS) {
            Iterator<SASLMechanism> it = REGISTERED_MECHANISMS.iterator();
            while (it.hasNext()) {
                SASLMechanism mechanism = it.next();
                if (mechanism.getClass().getName().equals(clazz)) {
                    it.remove();
                    return true;
                }
            }
        }
        return false;
    }
    public static boolean blacklistSASLMechanism(String mechansim) {
        synchronized(BLACKLISTED_MECHANISMS) {
            return BLACKLISTED_MECHANISMS.add(mechansim);
        }
    }
    public static boolean unBlacklistSASLMechanism(String mechanism) {
        synchronized(BLACKLISTED_MECHANISMS) {
            return BLACKLISTED_MECHANISMS.remove(mechanism);
        }
    }
    public static Set<String> getBlacklistedSASLMechanisms() {
        synchronized(BLACKLISTED_MECHANISMS) {
            return new HashSet<String>(BLACKLISTED_MECHANISMS);
        }
    }

    private final HSXMPPTCPConnection connection;
    private SASLMechanism currentMechanism = null;
    private boolean authenticationSuccessful;
    private Exception saslException;

    public SASLAuthentication(HSXMPPTCPConnection connection) {
        this.connection = connection;
        this.init();
    }

    public boolean hasAnonymousAuthentication() {
        return serverMechanisms().contains("ANONYMOUS");
    }
    public boolean hasNonAnonymousAuthentication() {
        return !serverMechanisms().isEmpty() && (serverMechanisms().size() != 1 || !hasAnonymousAuthentication());
    }

    public void authenticate(String resource, CallbackHandler cbh) throws IOException,
            XMPPErrorException, SASLErrorException, SmackException {
        SASLMechanism selectedMechanism = selectMechanism();
        if (selectedMechanism != null) {
            currentMechanism = selectedMechanism;
            synchronized (this) {
                currentMechanism.authenticate(connection.getHost(), connection.getServiceName(), cbh);
                try {
                    // Wait until SASL negotiation finishes
                    wait(connection.getPacketReplyTimeout());
                }
                catch (InterruptedException e) {
                    // Ignore
                }
            }

            maybeThrowException();

            if (!authenticationSuccessful) {
                throw NoResponseException.newWith(connection);
            }
        }
        else {
            throw new SmackException(
                    "SASL Authentication failed. No known authentication mechanisims.");
        }
    }

    public void authenticate(String username, String password, String resource)
            throws XMPPErrorException, SASLErrorException, IOException,
            SmackException {
        SASLMechanism selectedMechanism = selectMechanism();
        if (selectedMechanism != null) {
            currentMechanism = selectedMechanism;

            synchronized (this) {
                currentMechanism.authenticate(username, connection.getHost(),
                        connection.getServiceName(), password);
                try {
                    // Wait until SASL negotiation finishes
                    wait(connection.getPacketReplyTimeout());
                }
                catch (InterruptedException e) {
                    // Ignore
                }
            }

            maybeThrowException();

            if (!authenticationSuccessful) {
                throw SmackException.NoResponseException.newWith(connection);
            }
        }
        else {
            throw new SmackException(
                    "SASL Authentication failed. No known authentication mechanisims.");
        }
    }

    public void authenticateAnonymously() throws SASLErrorException,
            SmackException, XMPPErrorException {
        currentMechanism = (new SASLAnonymous()).instanceForAuthentication(connection);

        // Wait until SASL negotiation finishes
        synchronized (this) {
            currentMechanism.authenticate(null, null, null, "");
            try {
                wait(connection.getPacketReplyTimeout());
            }
            catch (InterruptedException e) {
                // Ignore
            }
        }

        maybeThrowException();

        if (!authenticationSuccessful) {
            throw NoResponseException.newWith(connection);
        }
    }

    private void maybeThrowException() throws SmackException, SASLErrorException {
        if (saslException != null){
            if (saslException instanceof SmackException) {
                throw (SmackException) saslException;
            } else if (saslException instanceof SASLErrorException) {
                throw (SASLErrorException) saslException;
            } else {
                throw new IllegalStateException("Unexpected exception type" , saslException);
            }
        }
    }

    public void challengeReceived(String challenge) throws SmackException {
        challengeReceived(challenge, false);
    }

    public void challengeReceived(String challenge, boolean finalChallenge) throws SmackException {
        try {
            currentMechanism.challengeReceived(challenge, finalChallenge);
        } catch (SmackException e) {
            authenticationFailed(e);
            throw e;
        }
    }

    public void authenticated(Success success) throws SmackException {
        if (success.getData() != null) {
            challengeReceived(success.getData(), true);
        }
        currentMechanism.checkIfSuccessfulOrThrow();
        authenticationSuccessful = true;
        // Wake up the thread that is waiting in the #authenticate method
        synchronized (this) {
            notify();
        }
    }

    public void authenticationFailed(SASLFailure saslFailure) {
        authenticationFailed(new SASLErrorException(currentMechanism.getName(), saslFailure));
    }

    public void authenticationFailed(Exception exception) {
        saslException = exception;
        // Wake up the thread that is waiting in the #authenticate method
        synchronized (this) {
            notify();
        }
    }
    public boolean authenticationSuccessful() {
        return authenticationSuccessful;
    }
    public void init() {
        authenticationSuccessful = false;
        saslException = null;
    }

    private SASLMechanism selectMechanism() {
        // Locate the SASLMechanism to use
        SASLMechanism selectedMechanism = null;
        Iterator<SASLMechanism> it = REGISTERED_MECHANISMS.iterator();
        // Iterate in SASL Priority order over registered mechanisms
        while (it.hasNext()) {
            SASLMechanism mechanism = it.next();
            String mechanismName = mechanism.getName();
            synchronized (BLACKLISTED_MECHANISMS) {
                if (BLACKLISTED_MECHANISMS.contains(mechanismName)) {
                    continue;
                }
            }
            if (serverMechanisms().contains(mechanismName)) {
                // Create a new instance of the SASLMechanism for every authentication attempt.
                selectedMechanism = mechanism.instanceForAuthentication(connection);
                break;
            }
        }
        return selectedMechanism;
    }

    private List<String> serverMechanisms() {
        Mechanisms mechanisms = connection.getFeature(Mechanisms.ELEMENT, Mechanisms.NAMESPACE);
        if (mechanisms == null) {
            LOGGER.warning("Server did not report any SASL mechanisms");
            return Collections.emptyList();
        }
        return mechanisms.getMechanisms();
    }
}
