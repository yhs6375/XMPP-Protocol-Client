package socket.xmpp.builder;

import socket.xmpp.HSXMPPTCPConnection;

public interface ConnectionListener {
    public void connected(HSXMPPTCPConnection connection);
    public void connectionClosed();
    public void connectionClosedOnError(Exception e);
    public void reconnectingIn(int seconds);
    public void reconnectionFailed(Exception e);
    public void reconnectionSuccessful();
    public void authenticated(HSXMPPTCPConnection connection, boolean resumed);
}
