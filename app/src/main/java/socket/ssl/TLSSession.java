package socket.ssl;

import android.util.Log;

import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import util.HSTask;

/**
 * Created by hosung on 2017-04-09.
 */

public class TLSSession{
    public TLSSession(){
        TLSConnectTest connTest=new TLSConnectTest();
        connTest.execute();
    }
    private class TLSConnectTest extends HSTask<byte[],Integer,Integer> {
        @Override
        protected Integer doInBackground(byte[]... datas){
            try{
                TLSBuild a=new TLSBuild();
                SSLSocket newSocket=a.createSocket("test.hodofactory.com",443);
                SSLSession session = newSocket.getSession();

                OutputStream socketOutput=newSocket.getOutputStream();
                socketOutput.write("hehe".getBytes());
                newSocket.close();
            }catch(CertificateException e){Log.d("HS","Cert관련 : "+e.getMessage());e.printStackTrace();}
            catch(KeyStoreException e){Log.d("HS","KeyStore관련 : "+e.getMessage());e.printStackTrace();}
            catch(NoSuchAlgorithmException e){Log.d("HS","NoSuchAlgorithm관련 : "+e.getMessage());e.printStackTrace();}
            catch(IOException e){Log.d("HS","IO관련 : "+e.getMessage());e.printStackTrace();}
            catch(KeyManagementException e){Log.d("HS","KeyManagement관련 : "+e.getMessage());e.printStackTrace();}
            catch(UnrecoverableKeyException e){Log.d("HS","UnrecoverableKey관련 : "+e.getMessage());e.printStackTrace();}
            return null;
        }
    }
}
