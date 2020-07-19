package socket.xmpp.packet;

import java.io.Reader;
import java.util.logging.Level;

public class PacketParserUtils {
    public static XmlPullParser newXmppParser(Reader reader) throws XmlPullParserException {
        XmlPullParser parser = newXmppParser();
        parser.setInput(reader);
        return parser;
    }
    public static XmlPullParser newXmppParser() throws XmlPullParserException {
        XmlPullParser parser = XmlPullParserFactory.newInstance().newPullParser();
        parser.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, true);
        if (XML_PULL_PARSER_SUPPORTS_ROUNDTRIP) {
            try {
                parser.setFeature(FEATURE_XML_ROUNDTRIP, true);
            }
            catch (XmlPullParserException e) {
                LOGGER.log(Level.SEVERE,
                        "XmlPullParser does not support XML_ROUNDTRIP, although it was first determined to be supported",
                        e);
            }
        }
        return parser;
    }
}
