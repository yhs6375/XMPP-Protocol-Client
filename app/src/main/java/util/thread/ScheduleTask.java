package util.thread;

import org.spongycastle.jcajce.provider.symmetric.ARC4;

import java.util.concurrent.Callable;

/**
 * Created by hosung on 2017-03-31.
 */

public class ScheduleTask<V> extends BaseTask{
    private int state=NEW;
    private volatile Thread thread;
    private Callable callable;

    public ScheduleTask(Callable callable){
        this.taskType=SCHEDULE_TASK;
        if (callable == null)
            throw new NullPointerException();
        this.callable=callable;
    }
    public void run(){
        thread=Thread.currentThread();
        state=PROGRESS;
        try{
            callable.call();
        }catch(Exception e){

        }
    }
    protected void done(){}
}
