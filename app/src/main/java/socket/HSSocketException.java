package socket;

import org.jivesoftware.smack.filter.StanzaFilter;

import java.net.InetAddress;

import socket.xmpp.HSXMPPTCPConnection;

public class HSSocketException extends Exception{
    public HSSocketException(Throwable wrappedThrowable) {
        super(wrappedThrowable);
    }
    public HSSocketException(String message){
        super(message);
    }
    public HSSocketException(String message, Throwable wrappedThrowable) {
        super(message, wrappedThrowable);
    }
    protected HSSocketException() {
    }
    public static class NotConnectedException extends HSSocketException{
        public NotConnectedException() {
            this(null);
        }
        public NotConnectedException(String optionalHint) {
            super("The Client is not connected to the server or no longer." + (optionalHint != null ? ' ' + optionalHint : ""));
        }
    }
    public static class AlreadyConnectedException extends HSSocketException {
        public AlreadyConnectedException() {
            super("Client is already connected");
        }
    }
    public static class ConnectionException extends HSSocketException{
        private InetAddress failedAddress;
        public ConnectionException(Throwable wrappedThrowable) {
            super(wrappedThrowable);
        }
        public ConnectionException(String message) {
            super(message);
        }
        public ConnectionException(String message, Throwable wrappedThrowable) {
            super(message, wrappedThrowable);
        }
        public void setFailedAddress(InetAddress failedAddress){this.failedAddress=failedAddress;}
        public InetAddress getFailedAddress() {
            return failedAddress;
        }
    }
    public static class NoResponseException extends HSSocketException {
        private final StanzaFilter filter;

        private NoResponseException(String message, StanzaFilter filter) {
            super(message);
            this.filter = filter;
        }

        /**
         * Get the filter that was used to collect the response.
         *
         * @return the used filter or <code>null</code>.
         */
        public StanzaFilter getFilter() {
            return filter;
        }

        public static NoResponseException newWith(HSXMPPTCPConnection connection) {
            return newWith(connection, (StanzaFilter) null);
        }

        public static NoResponseException newWith(HSXMPPTCPConnection connection, PacketCollector collector) {
            return newWith(connection, collector.getStanzaFilter());
        }

        public static NoResponseException newWith(HSXMPPTCPConnection connection, StanzaFilter filter) {
            final long replyTimeout = connection.getPacketReplyTimeout();
            final StringBuilder sb = new StringBuilder(256);
            sb.append("No response received within reply timeout. Timeout was " + replyTimeout + "ms (~" + replyTimeout / 1000 + "s). Used filter: ");
            if (filter != null) {
                sb.append(filter.toString());
            }
            else {
                sb.append("No filter used or filter was 'null'");
            }
            sb.append('.');
            return new NoResponseException(sb.toString(), filter);
        }

    }
}
