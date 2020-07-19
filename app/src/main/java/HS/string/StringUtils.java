package HS.string;

import java.io.UnsupportedEncodingException;

/**
 * Created by hosung on 2017-06-09.
 */

public class StringUtils {
    public static final String UTF8 = "UTF-8";
    public static String charSequenceToString(CharSequence cs){
        if(cs==null){
            return null;
        }
        return cs.toString();
    }
    public static boolean isEmpty(CharSequence cs) {
        return cs.length() == 0;
    }
    public static boolean isNullOrEmpty(CharSequence cs) {
        return cs == null || isEmpty(cs);
    }
    public static boolean isNotNullOrEmpty(CharSequence cs) {
        return !isNullOrEmpty(cs);
    }
    public static byte[] toBytes(String string) {
        try {
            return string.getBytes(StringUtils.UTF8);
        }
        catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 encoding not supported by platform", e);
        }
    }
}
