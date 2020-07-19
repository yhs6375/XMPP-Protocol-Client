package socket.xmpp.packet;

import HS.string.StringUtils;
import HS.string.XmlStringBuilder;

public class StreamOpen extends FullStreamElement {
    public static final String ELEMENT = "stream:stream";
    public static final String CLIENT_NAMESPACE = "jabber:client";
    public static final String SERVER_NAMESPACE = "jabber:server";
    public static final String VERSION = "1.0";
    private final String from;
    private final String to;
    private final String id;
    private final String lang;
    private final String contentNamespace;

    public StreamOpen(CharSequence to) {
        this(to, null, null, null, StreamContentNamespace.client);
    }

    public StreamOpen(CharSequence to, CharSequence from, String id) {
        this(to, from, id, "en", StreamContentNamespace.client);
    }

    public StreamOpen(CharSequence to, CharSequence from, String id, String lang, StreamContentNamespace ns) {
        this.to = StringUtils.charSequenceToString(to);
        this.from = StringUtils.charSequenceToString(from);
        this.id = id;
        this.lang = lang;
        switch (ns) {
            case client:
                this.contentNamespace = CLIENT_NAMESPACE;
                break;
            case server:
                this.contentNamespace = SERVER_NAMESPACE;
                break;
            default:
                throw new IllegalStateException();
        }
    }
    public String getNamespace() {
        return contentNamespace;
    }
    public String getElementName() {
        return ELEMENT;
    }
    public XmlStringBuilder toXML() {
        XmlStringBuilder xml = new XmlStringBuilder(this);
        xml.attribute("to", to);
        xml.attribute("xmlns:stream", "http://etherx.jabber.org/streams");
        xml.attribute("version", VERSION);
        xml.optAttribute("from", from);
        xml.optAttribute("id", id);
        xml.xmllangAttribute(lang);
        xml.rightAngleBracket();
        return xml;
    }

    public enum StreamContentNamespace {
        client,
        server;
    }
}
