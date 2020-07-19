package socket.xmpp.builder;

import socket.xmpp.HSXMPPTCPConnection;

public class AbstractConnectionListener implements ConnectionListener{
    @Override
    public void connected(HSXMPPTCPConnection connection) {
        // do nothing
    }

    @Override
    public void authenticated(HSXMPPTCPConnection connection, boolean resumed) {
        // do nothing
    }

    @Override
    public void connectionClosed() {
        // do nothing
    }

    @Override
    public void connectionClosedOnError(Exception e) {
        // do nothing
    }

    @Override
    public void reconnectingIn(int seconds) {
        // do nothing
    }

    @Override
    public void reconnectionFailed(Exception e) {
        // do nothing
    }

    @Override
    public void reconnectionSuccessful() {
        // do nothing
    }
}
