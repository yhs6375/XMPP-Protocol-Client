package util;

import android.os.AsyncTask;
import android.os.Binder;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.Process;
import android.support.annotation.MainThread;
import android.support.annotation.WorkerThread;
import android.util.Log;

import org.spongycastle.jcajce.provider.symmetric.ARC4;

import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import util.thread.BaseTask;
import util.thread.DefaultTask;
import util.thread.HSLinkedQueue;
import util.thread.HSThreadPool;
import util.thread.ScheduleTask;

import static java.lang.Thread.sleep;

public abstract class HSTask<Params, Progress, Result> {
    private static final String LOG_TAG = "HSThread";

    private static final int CPU_COUNT = Runtime.getRuntime().availableProcessors();
    private static final int CORE_POOL_SIZE = Math.max(2, CPU_COUNT);
    //private static final int CORE_POOL_SIZE = 4;
    private static final int KEEP_ALIVE_SECONDS = 30;

    private static final ThreadFactory sThreadFactory = new ThreadFactory() {
        private final AtomicInteger mCount = new AtomicInteger(1);

        public Thread newThread(Runnable r) {
            return new Thread(r, "HSTask #" + mCount.getAndIncrement());
        }
    };
    private static final HSLinkedQueue<Runnable> baseQueue = new HSLinkedQueue<Runnable>(128);
    private static final HSLinkedQueue<Runnable> scheduleQueue = new HSLinkedQueue<Runnable>(128);
    public static final HSThreadPool THREAD_POOL_EXECUTOR;

    static {
        HSThreadPool threadPoolExecutor = new HSThreadPool(
                CORE_POOL_SIZE, KEEP_ALIVE_SECONDS,baseQueue,
                scheduleQueue, sThreadFactory);
        THREAD_POOL_EXECUTOR = threadPoolExecutor;
    }

    private static final int MESSAGE_POST_RESULT = 0x1;
    private static final int MESSAGE_POST_PROGRESS = 0x2;

    private static InternalHandler sHandler;

    private BaseTask<Result> workTask;

    private volatile Status mStatus = Status.PENDING;

    private final AtomicBoolean mCancelled = new AtomicBoolean();
    private final AtomicBoolean mTaskInvoked = new AtomicBoolean();

    private Thread.UncaughtExceptionHandler exceptionHandler;
    private WorkerRunnable workerRunnable;
    private static abstract class WorkerRunnable<Params, Result> implements Callable{
        Params[] mParams;
    }

    public enum Status {
        PENDING,
        RUNNING,
        FINISHED,
    }

    //핸들러 관련 시작
    private static Handler getHandler() {
        synchronized (HSTask.class) {
            if (sHandler == null) {
                sHandler = new InternalHandler();
            }
            return sHandler;
        }
    }
    private static class InternalHandler extends Handler {
        public InternalHandler() {
            super(Looper.getMainLooper());
        }
        @SuppressWarnings({"unchecked", "RawUseOfParameterizedType"})
        @Override
        public void handleMessage(Message msg) {
            TaskResult<?> result = (TaskResult<?>) msg.obj;
            switch (msg.what) {
                case MESSAGE_POST_RESULT:
                    result.mTask.finish(result.mData[0]);
                    break;
                case MESSAGE_POST_PROGRESS:
                    result.mTask.onProgressUpdate(result.mData);
                    break;
            }
        }
    }
    @SuppressWarnings({"RawUseOfParameterizedType"})
    private static class TaskResult<Data> {
        final HSTask mTask;
        final Data[] mData;

        TaskResult(HSTask task, Data... data) {
            mTask = task;
            mData = data;
        }
    }
    private Result postResult(Result result) { //메인쓰레드로 메시지 전송
        @SuppressWarnings("unchecked")
        Message message = getHandler().obtainMessage(MESSAGE_POST_RESULT, new TaskResult<Result>(this, result));
        message.sendToTarget();
        return result;
    }
    @WorkerThread
    protected final void publishProgress(Progress... values) {
        if (!isCancelled()) {
            getHandler().obtainMessage(MESSAGE_POST_PROGRESS, new TaskResult<Progress>(this, values)).sendToTarget();
        }
    }
    //핸들러 관련 끝
    //에러 관련 시작
    class ThreadExceptionHandler implements Thread.UncaughtExceptionHandler {
        @Override
        public void uncaughtException(Thread thread, Throwable err) {
            onError(thread,err);
        }
    }
    //에러 관련 끝
    public HSTask() {
        this(BaseTask.DEFAULT_TASK,Process.THREAD_PRIORITY_BACKGROUND);
    }
    public HSTask(int priority) {
        this(BaseTask.DEFAULT_TASK,priority);
    }
    public HSTask(int taskType,final int priority){
        workerRunnable=new WorkerRunnable<Params,Result>() {
            @Override
            public Result call() throws Exception {
                mTaskInvoked.set(true);
                Result result = null;
                try {
                    Process.setThreadPriority(priority);
                    result = doInBackground(mParams);
                    Binder.flushPendingCommands();
                } catch (Throwable tr) {
                    mCancelled.set(true);
                    throw tr;
                } finally {
                    postResult(result);
                }
                return result;
            }
        };
        if(taskType==BaseTask.DEFAULT_TASK){
            workTask = new DefaultTask<Result>(workerRunnable);
        }else{

        }
    }
    public HSTask(Runnable work){
        THREAD_POOL_EXECUTOR.execute(work);
    }
    public HSTask(Runnable work, Thread.UncaughtExceptionHandler errHandler){
        THREAD_POOL_EXECUTOR.execute(work,errHandler);
    }

    public final Status getStatus() {
        return mStatus;
    }

    @WorkerThread
    protected abstract Result doInBackground(Params... params);

    @MainThread
    protected void onPreExecute() {}
    @SuppressWarnings({"UnusedDeclaration"})
    @MainThread
    protected void onPostExecute(Result result) {}
    @SuppressWarnings({"UnusedDeclaration"})
    @MainThread
    protected void onProgressUpdate(Progress... values) {}
    @SuppressWarnings({"UnusedParameters"})
    @MainThread
    protected void onCancelled(Result result) {}
    @MainThread
    protected void onError(Thread thread,Throwable e){}
    public final boolean isCancelled() {
        return mCancelled.get();
    }

    public final void cancel(){
        mCancelled.set(true);
        workTask.cancel();
    }
    @MainThread
    public final HSTask<Params, Progress, Result> execute(Params... params) {
        if (mStatus != Status.PENDING) {
            switch (mStatus) {
                case RUNNING:
                    throw new IllegalStateException("Cannot execute task:"
                            + " the task is already running.");
                case FINISHED:
                    throw new IllegalStateException("Cannot execute task:"
                            + " the task has already been executed "
                            + "(a task can be executed only once)");
            }
        }
        mStatus = Status.RUNNING;

        onPreExecute();
        workerRunnable.mParams = params;
        THREAD_POOL_EXECUTOR.execute(workTask);
        return this;
    }
    private void finish(Result result) {
        if (isCancelled()) {
            onCancelled(result);
        } else {
            onPostExecute(result);
        }
        mStatus = Status.FINISHED;
    }
}