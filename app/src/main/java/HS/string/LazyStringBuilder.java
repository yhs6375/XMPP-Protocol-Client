package HS.string;

import java.util.ArrayList;
import java.util.List;

public class LazyStringBuilder implements Appendable, CharSequence {

    private final List<CharSequence> list;

    private String cache;

    private void invalidateCache() {
        cache = null;
    }

    public LazyStringBuilder() {
        list = new ArrayList<CharSequence>(20);
    }
    public LazyStringBuilder(short size){
        list=new ArrayList<CharSequence>(size);
    }

    public LazyStringBuilder append(LazyStringBuilder lsb) {
        list.addAll(lsb.list);
        invalidateCache();
        return this;
    }

    @Override
    public LazyStringBuilder append(CharSequence cs) {
        assert cs != null;
        list.add(cs);
        invalidateCache();
        return this;
    }

    @Override
    public LazyStringBuilder append(CharSequence cs, int start, int end) {
        CharSequence subsequence = cs.subSequence(start, end);
        list.add(subsequence);
        invalidateCache();
        return this;
    }

    @Override
    public LazyStringBuilder append(char c) {
        list.add(Character.toString(c));
        invalidateCache();
        return this;
    }

    @Override
    public int length() {
        if (cache != null) {
            return cache.length();
        }
        int length = 0;
        for (CharSequence csq : list) {
            length += csq.length();
        }
        return length;
    }

    @Override
    public char charAt(int index) {
        if (cache != null) {
            return cache.charAt(index);
        }
        for (CharSequence csq : list) {
            if (index < csq.length()) {
                return csq.charAt(index);
            } else {
                index -= csq.length();
            }
        }
        throw new IndexOutOfBoundsException();
    }

    @Override
    public CharSequence subSequence(int start, int end) {
        return toString().subSequence(start, end);
    }

    @Override
    public String toString() {
        if (cache == null) {
            StringBuilder sb = new StringBuilder(length());
            for (CharSequence csq : list) {
                sb.append(csq);
            }
            cache = sb.toString();
        }
        return cache;
    }
}
