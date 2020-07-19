package socket.ssl;

import android.util.Base64;
import android.util.Log;

import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.pkcs.PKCS10CertificationRequest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Created by hosung on 2017-03-19.
 */

public class MakeKeyPairAndCSR {
    final static int KEY_SIZE=2048;

    //RSA 키쌍을 생성.
    static public KeyPair makeKeyPair() throws NoSuchAlgorithmException{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(KEY_SIZE, new SecureRandom());
        return keyGen.generateKeyPair();
    }
    //Client Certificate Request를 생성
    static public byte[] makeCSR(KeyPair keyPair) throws IOException,OperatorCreationException{
        PKCS10CertificationRequest csr = CSRHelper.generateCSR(keyPair);
        byte[] start="-----BEGIN CERTIFICATE REQUEST-----\n".getBytes();
        byte[] end="-----END CERTIFICATE REQUEST-----".getBytes();
        byte CSRder[] = Base64.encode(csr.getEncoded(),Base64.DEFAULT);
        ByteBuffer bb=ByteBuffer.allocate(start.length+CSRder.length+end.length);
        bb.put(start);
        bb.put(CSRder);
        bb.put(end);
        return bb.array();
    }
}
