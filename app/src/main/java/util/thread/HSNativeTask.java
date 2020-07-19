package util.thread;

/**
 * Created by hosung on 2017-03-27.
 */

public class HSNativeTask {
    private static final String LOG_TAG = "HSThread";
    private static final int CPU_COUNT = Runtime.getRuntime().availableProcessors();
    private static final int CORE_POOL_SIZE = Math.max(2, Math.min(CPU_COUNT - 1, 4));
    private static final int IDLE_TIME_OUT_SECONDS=30;

    static{
        //HSThreadPool pool=new HSThreadPool(CORE_POOL_SIZE,IDLE_TIME_OUT_SECONDS);

    }
}
