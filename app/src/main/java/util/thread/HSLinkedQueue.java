package util.thread;

import android.util.Log;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class HSLinkedQueue<T> {
    private final int capacity;
    private final AtomicInteger count = new AtomicInteger();

    private final ReentrantLock putLock = new ReentrantLock();
    private final ReentrantLock takeLock = new ReentrantLock();
    private final Condition notEmpty = takeLock.newCondition();
    private final Condition notFull = takeLock.newCondition();

    private class Node{
        private T data;
        private Node next;
        Node(T data){
            this.data = data;
            this.next = null;
        }
    }
    private Node head;
    private Node last;

    public HSLinkedQueue(){
        this(Integer.MAX_VALUE);
    }
    public HSLinkedQueue(int value){
        last = head = null;
        capacity=value;
    }
    private void signalNotEmpty() {
        final ReentrantLock takeLock = this.takeLock;
        takeLock.lock();
        try {
            notEmpty.signal();
        } finally {
            takeLock.unlock();
        }
    }
    private void signalNotFull() {
        final ReentrantLock putLock = this.putLock;
        putLock.lock();
        try {
            notFull.signal();
        } finally {
            putLock.unlock();
        }
    }
    void PutTakeLock() {
        putLock.lock();
        takeLock.lock();
    }
    void PutTakeUnlock() {
        takeLock.unlock();
        putLock.unlock();
    }
    public boolean isEmpty(){
        return (head==null);
    }
    public T peek(){
        if(isEmpty()) throw new ArrayIndexOutOfBoundsException();
        return head.data;
    }

    public boolean insert(T item){
        if (item == null) throw new NullPointerException();
        final AtomicInteger count = this.count;
        if(count.get()==capacity){
            return false;
        }
        int c = -1;
        Node node = new Node(item);
        putLock.lock();
        try{
            if (count.get() < capacity) {
                enqueue(node);
                c=count.getAndIncrement();
            }
        }finally {
            putLock.unlock();
        }
        if(c==0){
            signalNotEmpty();
        }
        return true;
    }
    public T pollTime(long timeout,TimeUnit unit) throws InterruptedException{
        T x = null;
        int c = -1;
        long nanos = unit.toNanos(timeout);
        final AtomicInteger count = this.count;
        final ReentrantLock takeLock = this.takeLock;
        takeLock.lockInterruptibly();
        try {
            while (count.get() == 0) {
                if (nanos <= 0L) {
                    return null;
                }
                nanos = notEmpty.awaitNanos(nanos);
            }
            x = dequeue();
            c = count.getAndDecrement();
            if (c > 1)
                notEmpty.signal();
        } finally {
            takeLock.unlock();
        }
        Log.d("HS",count.get()+"");
        if (c == capacity)
            signalNotFull();
        return x;
    }
    public T shift(){
        final AtomicInteger count = this.count;
        if (count.get() == 0)
            return null;
        T x = null;
        int c = -1;
        final ReentrantLock takeLock = this.takeLock;
        takeLock.lock();
        try {
            if (count.get() > 0) {
                x = dequeue();
                c = count.getAndDecrement();
                if (c > 1)
                    notEmpty.signal();
            }
        } finally {
            takeLock.unlock();
        }
        if (c == capacity)
            signalNotFull();
        return x;
    }

    public boolean remove(Object o) {
        if (o == null) return false;
        PutTakeLock();
        try {
            for (Node trail=head,p=trail.next; p != null; trail = p, p = p.next){
                if (o.equals(p.data)){
                    unlink(p,trail);
                    return true;
                }
            }
            return false;
        } finally {
            PutTakeUnlock();
        }
    }
    void unlink(Node p, Node trail){
        p.data = null;
        trail.next = p.next;
        if (last == p)
            last = trail;
        if (count.getAndDecrement() == capacity)
            notFull.signal();
    }
    private void enqueue(Node node) {
        if(head==null){
            last=head=node;
        }else{
            last=last.next=node;
        }
    }
    private T dequeue() {
        T x=head.data;
        if(head==last){
            head=last=null;
        }else{
            head=head.next;
        }
        return x;
    }
    public int remainingCapacity() {
        return capacity - count.get();
    }
    public int size(){
        return count.get();
    }
}
