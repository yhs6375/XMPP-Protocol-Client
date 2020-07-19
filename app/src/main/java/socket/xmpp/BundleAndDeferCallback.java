package socket.xmpp;

import socket.xmpp.BundleAndDefer;

public interface BundleAndDeferCallback {

    /**
     * Return the bundle and defer period used by Smack in milliseconds.
     *
     * @param bundleAndDefer used to premature abort bundle and defer.
     * @return the bundle and defer period in milliseconds.
     */
    public int getBundleAndDeferMillis(BundleAndDefer bundleAndDefer);

}
