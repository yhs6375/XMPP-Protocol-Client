package socket.xmpp;

import org.jivesoftware.smack.SmackException;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.logging.Level;
import java.util.logging.Logger;

import socket.HSSocketException.NoResponseException;

public class SynchronizationPoint<E extends Exception> {
    private static final Logger LOGGER = Logger.getLogger(SynchronizationPoint.class.getName());
    private final HSXMPPTCPConnection connection;
    private final Lock connectionLock;
    private final Condition condition;
    private State state;
    private E failureException;

    public SynchronizationPoint(HSXMPPTCPConnection connection) {
        this.connection = connection;
        this.connectionLock = connection.getConnectionLock();
        this.condition = connection.getConnectionLock().newCondition();
        init();
    }

    /**
     * Initialize (or reset) this synchronization point.
     */
    public void init() {
        connectionLock.lock();
        state = State.Initial;
        failureException = null;
        connectionLock.unlock();
    }

    /**
     * Send the given top level stream element and wait for a response.
     *
     * @param request the plain stream element to send.
     * @throws NoResponseException if no response was received.
     * @throws NotConnectedException if the connection is not connected.
     */
    public void sendAndWaitForResponse(TopLevelStreamElement request) throws NoResponseException,
            NotConnectedException {
        assert (state == State.Initial);
        connectionLock.lock();
        try {
            if (request != null) {
                if (request instanceof Stanza) {
                    connection.sendStanza((Stanza) request);
                }
                else if (request instanceof PlainStreamElement){
                    connection.send((PlainStreamElement) request);
                } else {
                    throw new IllegalStateException("Unsupported element type");
                }
                state = State.RequestSent;
            }
            waitForConditionOrTimeout();
        }
        finally {
            connectionLock.unlock();
        }
        checkForResponse();
    }

    /**
     * Send the given plain stream element and wait for a response.
     *
     * @param request the plain stream element to send.
     * @throws E if an failure was reported.
     * @throws NoResponseException if no response was received.
     * @throws NotConnectedException if the connection is not connected.
     */
    public void sendAndWaitForResponseOrThrow(PlainStreamElement request) throws E, NoResponseException,
            NotConnectedException {
        sendAndWaitForResponse(request);
        switch (state) {
            case Failure:
                if (failureException != null) {
                    throw failureException;
                }
                break;
            default:
                // Success, do nothing
        }
    }

    /**
     * Check if this synchronization point is successful or wait the connections reply timeout.
     * @throws NoResponseException if there was no response marking the synchronization point as success or failed.
     * @throws E if there was a failure
     */
    public void checkIfSuccessOrWaitOrThrow() throws NoResponseException, E {
        checkIfSuccessOrWait();
        if (state == State.Failure) {
            throw failureException;
        }
    }

    /**
     * Check if this synchronization point is successful or wait the connections reply timeout.
     * @throws NoResponseException if there was no response marking the synchronization point as success or failed.
     */
    public void checkIfSuccessOrWait() throws NoResponseException {
        connectionLock.lock();
        try {
            if (state == State.Success) {
                // Return immediately
                return;
            }
            waitForConditionOrTimeout();
        } finally {
            connectionLock.unlock();
        }
        checkForResponse();
    }

    /**
     * Report this synchronization point as successful.
     */
    public void reportSuccess() {
        connectionLock.lock();
        try {
            state = State.Success;
            condition.signalAll();
        }
        finally {
            connectionLock.unlock();
        }
    }

    /**
     * Deprecated
     * @deprecated use {@link #reportFailure(Exception)} instead.
     */
    @Deprecated
    public void reportFailure() {
        reportFailure(null);
    }

    /**
     * Report this synchronization point as failed because of the given exception. The {@code failureException} must be set.
     *
     * @param failureException the exception causing this synchronization point to fail.
     */
    public void reportFailure(E failureException) {
        assert failureException != null;
        connectionLock.lock();
        try {
            state = State.Failure;
            this.failureException = failureException;
            condition.signalAll();
        }
        finally {
            connectionLock.unlock();
        }
    }

    /**
     * Check if this synchronization point was successful.
     *
     * @return true if the synchronization point was successful, false otherwise.
     */
    public boolean wasSuccessful() {
        connectionLock.lock();
        try {
            return state == State.Success;
        }
        finally {
            connectionLock.unlock();
        }
    }

    /**
     * Check if this synchronization point has its request already sent.
     *
     * @return true if the request was already sent, false otherwise.
     */
    public boolean requestSent() {
        connectionLock.lock();
        try {
            return state == State.RequestSent;
        }
        finally {
            connectionLock.unlock();
        }
    }

    private void waitForConditionOrTimeout() {
        long remainingWait = TimeUnit.MILLISECONDS.toNanos(connection.getPacketReplyTimeout());
        while (state == State.RequestSent || state == State.Initial) {
            try {
                if (remainingWait <= 0) {
                    state = State.NoResponse;
                    break;
                }
                remainingWait = condition.awaitNanos(remainingWait);
            } catch (InterruptedException e) {
                LOGGER.log(Level.WARNING, "Thread interrupt while waiting for condition or timeout ignored", e);
            }
        }
    }

    private void checkForResponse() throws NoResponseException {
        switch (state) {
            case Initial:
            case NoResponse:
            case RequestSent:
                throw NoResponseException.newWith(connection);
            default:
                // Do nothing
                break;
        }
    }

    private enum State {
        Initial,
        RequestSent,
        NoResponse,
        Success,
        Failure,
    }
}
