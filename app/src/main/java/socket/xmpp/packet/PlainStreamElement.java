package socket.xmpp.packet;

/* Stanza가 아닌 모든것이다. RFC 6120 8번에 정의되어있다.
Stanza는 Message,Presence,IQ를 말한다.
이를 제외한 모든것은 Stanza클래스 대신 이 클래스의 자식클래스여야 한다.
stanza와 비stanza사이의 구분짓는건 중요하다.
 */
public interface PlainStreamElement extends TopLevelStreamElement {

}
