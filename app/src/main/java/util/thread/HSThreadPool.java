package util.thread;

import android.os.Process;
import android.util.Log;

import java.util.HashSet;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.AbstractQueuedSynchronizer;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Created by hosung on 2017-03-27.
 */

public class HSThreadPool {
    private final AtomicInteger ctl = new AtomicInteger(RUNNING);
    private static final int COUNT_BITS = Integer.SIZE - 3;
    private static final int CAPACITY   = (1 << COUNT_BITS) - 1;

    private static final int RUNNING    = -1 << COUNT_BITS;
    private static final int SHUTDOWN   =  0 << COUNT_BITS;
    private static final int STOP       =  1 << COUNT_BITS;
    private static final int TIDYING    =  2 << COUNT_BITS;
    private static final int TERMINATED =  3 << COUNT_BITS;

    private static int runStateOf(int c)     { return c & ~CAPACITY; }
    private static int workerCountOf(int c)  { return c & CAPACITY; }
    private static int ctlOf(int rs, int wc) { return rs | wc; }

    HSLinkedQueue<Runnable> baseQueue;
    HSLinkedQueue<Runnable> scheduleQueue;
    private volatile int corePoolSize;
    private volatile long keepAliveTime;
    private volatile ThreadFactory threadFactory;

    private final HashSet<Worker> workers = new HashSet<>();
    private final ReentrantLock mainLock = new ReentrantLock();

    private int largestPoolSize;

    private final class Worker implements Runnable {
        final Thread thread;
        Runnable firstTask;
        volatile long completedTasks;
        Worker(Runnable firstTask) {
            this.firstTask = firstTask;
            this.thread = threadFactory.newThread(this);
        }
        public void run() {
            runWorker(this);
        }
    }
    public HSThreadPool(int coreSize,long timeOut,HSLinkedQueue<Runnable> baseQueue,HSLinkedQueue<Runnable> scheduleQueue,ThreadFactory threadFactory){
        this.corePoolSize=coreSize;
        this.keepAliveTime=timeOut;
        this.baseQueue=baseQueue;
        this.scheduleQueue=scheduleQueue;
        this.threadFactory=threadFactory;
    }
    private static boolean isRunning(int c) {
        return c < SHUTDOWN;
    }
    private static boolean runStateAtLeast(int c, int s) {
        return c >= s;
    }
    //쓰레드가 작업 가져오기 만약 작업큐가 비었다면 keepAliveTime동안 대기
    private Runnable getTask(){
        Runnable r;
        boolean timeout=false;
        for(;;){
            try{
                r = baseQueue.pollTime(keepAliveTime, TimeUnit.SECONDS);
                if(r!=null){
                    return r;
                }
                timeout=true;
            }catch(InterruptedException e) {}
            if(timeout){
                return null;//쓰레드큐가 시간이지나도 계속비어있어서 쓰레드가 메모리만잡으니 종료하라고 null 리턴
            }
        }
    }
    public void execute(Runnable command) {
        execute(command,null);
    }
    public void execute(Runnable command, Thread.UncaughtExceptionHandler errHandler){
        if (command == null)
            throw new NullPointerException();
        int c = ctl.get();
        if(isRunning(c)){
            if (workerCountOf(c) < corePoolSize) { //현재 작동중인쓰레드 수가 corePoolSize보다 작으면 쓰레드 추가
                Log.d("HS","새로운 Thread 추가");
                if(addWorker(command,errHandler))
                    return;
                c = ctl.get();
            }else{ //현재 작동중인쓰레드 수가 corePoolSize랑 같으면 대기큐에 집어넣음.
                Log.d("HS","작업큐에 Task 추가");
                baseQueue.insert(command);
            }
        }
    }
    private boolean addWorker(Runnable firstTask,Thread.UncaughtExceptionHandler errHandler){
        int c = ctl.get(),
            rs = runStateOf(c),
            wc = workerCountOf(c);
        if (rs >= SHUTDOWN ||(wc >= CAPACITY || wc >=corePoolSize))
            return false;
        ctl.getAndIncrement();//Worker수 1 올리고 루프 탈출
        boolean workerStarted = false;
        boolean workerAdded = false;
        Worker w = null;
        try {
            w = new Worker(firstTask);
            final Thread t = w.thread;
            if(errHandler!=null){
                t.setDefaultUncaughtExceptionHandler(errHandler);
            }
            if (t != null){
                final ReentrantLock mainLock = this.mainLock;
                mainLock.lock();
                try {
                    rs = runStateOf(ctl.get());
                    if (rs < SHUTDOWN) {
                        if (t.isAlive())
                            throw new IllegalThreadStateException();
                        workers.add(w);
                        int s = workers.size();
                        if (s > largestPoolSize)
                            largestPoolSize = s;
                        workerAdded = true;
                    }
                } finally {
                    mainLock.unlock();
                }
                if (workerAdded) {
                    t.start();
                    workerStarted = true;
                }
            }
        } finally {
            if (!workerStarted)
                addWorkerFailed(w);
        }
        return workerStarted;
    }
    private void addWorkerFailed(Worker w) {
        final ReentrantLock mainLock = this.mainLock;
        mainLock.lock();
        try {
            if (w != null)
                workers.remove(w);
            ctl.getAndDecrement();
        } finally {
            mainLock.unlock();
        }
    }
    private void workerExit(Worker w) {
        Thread t=w.thread;
        mainLock.lock();
        try{
            ctl.getAndDecrement();
            t.interrupt();
        }finally{
            mainLock.unlock();
        }
    }
    final void runWorker(Worker w) {
        Thread wt = Thread.currentThread();
        Runnable task = w.firstTask;
        w.firstTask = null;
        try {
            do{
                try {
                    try {
                        task.run();
                    } catch (RuntimeException x) {
                        throw x;
                    } catch (Error x) {
                        throw x;
                    } catch (Throwable x) {
                        throw new Error(x);
                    }
                } finally {
                    task = null;
                    w.completedTasks++;
                    if(Thread.interrupted()&&runStateAtLeast(ctl.get(),STOP)){
                        wt.interrupt();
                    }
                }
            }while((task = getTask()) != null);
        } finally {
            Log.d("HS","쓰레드 종료");
            workerExit(w);
        }
    }
}
