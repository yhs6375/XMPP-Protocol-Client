package util.thread;

/**
 * Created by hosung on 2017-03-30.
 */

public class BaseTask<V> implements Runnable{
    public static final int DEFAULT_TASK=0x1;
    public static final int SCHEDULE_TASK=0x2;

    protected static final int NEW = 0x1;
    protected static final int PROGRESS = 0x2;
    protected static final int COMPLETING = 0x3;
    protected static final int INTERRUPTING = 0x4;
    protected static final int INTERRUPTED = 0x5;
    public int taskType;
    public void run(){}
    public void cancel(){}
}
