package socket.xmpp;
import java.util.concurrent.atomic.AtomicBoolean;
public class BundleAndDefer {

    private final AtomicBoolean isStopped;

    BundleAndDefer(AtomicBoolean isStopped) {
        this.isStopped = isStopped;
    }

    /**
     * Stop the bundle and defer mechanism that was started when this instance of {@link org.jivesoftware.smack.tcp.BundleAndDefer} was emitted by
     * Smack.
     * <p>
     * It is possible that the defer period already expired when this is invoked. In this case this method is basically
     * a no-op.
     * </p>
     */
    public void stopCurrentBundleAndDefer() {
        synchronized (isStopped) {
            if (isStopped.get()) {
                return;
            }
            isStopped.set(true);
            isStopped.notify();
        }
    }
}
