package util.thread;

import android.util.Log;

import java.util.concurrent.Callable;

/**
 * Created by hosung on 2017-03-31.
 */

public class DefaultTask<V> extends BaseTask{
    private int state=NEW;
    private volatile Thread thread;
    private Callable callable;

    public DefaultTask(Callable callable){
        this.taskType=DEFAULT_TASK;
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
    public void cancel(){
        Thread t=thread;
        if(state==PROGRESS){
            state=INTERRUPTING;
        }
        try{
            t.interrupt();
        }finally{
            state=INTERRUPTED;
        }

    }
    protected void done(){}
}
