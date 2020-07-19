package socket.xmpp.packet;

//Stream 엘리먼트를 위한 기본 클래스. stanza(message,presence,iq)가 아닌 모든것들은 Stanza대신 이 클래스의 서브클래스여야한다.
public abstract class FullStreamElement implements PlainStreamElement, ExtensionElement {

}
