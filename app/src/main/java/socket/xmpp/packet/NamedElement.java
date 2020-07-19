package socket.xmpp.packet;

import HS.xml.Element;

/* XML 엘리먼트를 대표하는 인터페이스. 이는 ExtensionElement랑 유사하지만,
namespace를 동반하지 않고 보통 stanza(/packet)확장의 자식 엘리먼트로써 포함되어진다. */
public interface NamedElement extends Element {
    //루트 엘리먼트의 이름을 반환한다.
    public String getElementName();
}
