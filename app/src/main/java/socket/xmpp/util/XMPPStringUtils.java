package socket.xmpp.util;

public class XMPPStringUtils {
    public static String completeJidFrom(CharSequence localpart, CharSequence domainpart) {
        return completeJidFrom(localpart != null ? localpart.toString() : null, domainpart.toString());
    }

    public static String completeJidFrom(String localpart, String domainpart) {
        return completeJidFrom(localpart, domainpart, null);
    }
    public static String completeJidFrom(CharSequence localpart, CharSequence domainpart, CharSequence resource) {
        return completeJidFrom(localpart != null ? localpart.toString() : null, domainpart.toString(),
                resource != null ? resource.toString() : null);
    }
    public static String completeJidFrom(String localpart, String domainpart, String resource) {
        if (domainpart == null) {
            throw new IllegalArgumentException("domainpart must not be null");
        }
        int localpartLength = localpart != null ? localpart.length() : 0;
        int domainpartLength = domainpart.length();
        int resourceLength = resource != null ? resource.length() : 0;
        int maxResLength = localpartLength + domainpartLength + resourceLength + 2;
        StringBuilder sb = new StringBuilder(maxResLength);
        if (localpartLength > 0) {
            sb.append(localpart).append('@');
        }
        sb.append(domainpart);
        if (resourceLength > 0) {
            sb.append('/').append(resource);
        }
        return sb.toString();
    }
}
