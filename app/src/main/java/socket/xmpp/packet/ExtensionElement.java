package socket.xmpp.packet;

/*
 * Interface to represent extension elements.
 * An extension element is an XML subdocument
 * with a root element name and namespace. Extension elements are used to provide
 * extended functionality beyond what is in the base XMPP specification. Examples of
 * extensions elements include message events, message properties, and extra presence data.
 * IQ stanzas have limited support for extension elements.
 * This class is used primarily for extended content in XMPP Stanzas, to act as so called "extension elements". For more
 * information see <a href="https://tools.ietf.org/html/rfc6120#section-8.4">RFC 6120 § 8.4 Extended Content</a>.
 */
public interface ExtensionElement extends NamedElement {
    //root 엘리먼트 XML namespace를 반환
    public String getNamespace();
}
