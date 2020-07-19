package HS.stringEncoder;

import java.io.UnsupportedEncodingException;

import HS.string.StringUtils;

public class Base64 {

    private static Base64.Encoder base64encoder;

    public static void setEncoder(Base64.Encoder encoder) {
        Objects.requireNonNull(encoder, "encoder must no be null");
        base64encoder = encoder;
    }

    public static final String encode(String string) {
        try {
            return encodeToString(string.getBytes(StringUtils.UTF8));
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 not supported", e);
        }
    }

    public static final String encodeToString(byte[] input) {
        byte[] bytes = encode(input);
        try {
            return new String(bytes, StringUtils.USASCII);
        } catch (UnsupportedEncodingException e) {
            throw new AssertionError(e);
        }
    }

    public static final String encodeToString(byte[] input, int offset, int len) {
        byte[] bytes = encode(input, offset, len);
        try {
            return new String(bytes, StringUtils.USASCII);
        } catch (UnsupportedEncodingException e) {
            throw new AssertionError(e);
        }
    }

    public static final byte[] encode(byte[] input) {
        return encode(input, 0, input.length);
    }

    public static final byte[] encode(byte[] input, int offset, int len) {
        return base64encoder.encode(input, offset, len);
    }

    public static final String decodeToString(String string) {
        byte[] bytes = decode(string);
        try {
            return new String(bytes, StringUtils.UTF8);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 not supported", e);
        }
    }

    public static final String decodeToString(byte[] input, int offset, int len) {
        byte[] bytes = decode(input, offset, len);
        try {
            return new String(bytes, StringUtils.UTF8);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 not supported", e);
        }
    }

    public static final byte[] decode(String string) {
        return base64encoder.decode(string);
    }

    public static final byte[] decode(byte[] input) {
        return base64encoder.decode(input, 0, input.length);
    }

    public static final byte[] decode(byte[] input, int offset, int len) {
        return base64encoder.decode(input, offset, len);
    }

    public interface Encoder {
        byte[] decode(String string);

        byte[] decode(byte[] input, int offset, int len);

        String encodeToString(byte[] input, int offset, int len);

        byte[] encode(byte[] input, int offset, int len);
    }
}
