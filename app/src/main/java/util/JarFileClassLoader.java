package util;

/**
 * Created by hosung on 2017-03-13.
 */

public class JarFileClassLoader extends ClassLoader {
    /*private byte[] loadClassFromJarFile(String className) {
        // 지정한 jar 파일로부터 className에 해당하는 클래스의
        // 바이트코드를 byte[] 배열로 읽어온다.
        return byteArr;
    }

    public synchronized class loadClass(String className, boolean resolveIt)
            throws ClassNotFoundException {

        Class klass = null;

        // 클래스를 로드할 때, 캐시를 사용할 수 있다.
        klass = (Class) cache.get(className);

        if (klass != null) return klass;

        // 캐시에 없을 경우, 시스템 클래스로더로부터
        // 지정한 클래스가 있는 지 알아본다.
        try {
            klass = super.findSystemClass(className);
            return klass;
        } catch(ClassNotFoundException ex) {
            // do nothing
        }

        // Jar 파일로부터 className이 나타내는 클래스를 읽어온다.
        byte[] byteArray = loadClassFromJarFile(className);
        klass = defineClass(byteArray, 0, byteArray.length);
        if (resolve)
            resolveClass(klass);
        cache.put(className, klass); // 캐시에 추가
        return klass;
    }*/
}