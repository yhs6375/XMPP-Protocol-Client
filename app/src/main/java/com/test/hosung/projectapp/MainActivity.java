package com.test.hosung.projectapp;

import android.os.Handler;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;

import java.io.IOException;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import socket.HSSocketClient;
import socket.ssl.TLSBuild;
import socket.ssl.TLSInitiateKey;
import socket.ssl.TLSSession;
import util.HSTask;

public class MainActivity extends AppCompatActivity {
    XMPP xmpp=new XMPP();
    Handler mHandler;
    KeyStore androidStore;
    volatile boolean check=true;
    @Override
    protected void onCreate(Bundle savedInstanceState){
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Button but=(Button)findViewById(R.id.btnPhoneAuth);
        /*but.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                SignedPreKeyRecord signedPreKey = null;
                int startId = 1001;
                IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();
                int registrationId = KeyHelper.generateRegistrationId(true);
                List<PreKeyRecord> preKeys = KeyHelper.generatePreKeys(startId, 100);
                try {
                    signedPreKey = KeyHelper.generateSignedPreKey(identityKeyPair, 5);
                } catch (InvalidKeyException e) {

                }
                KeyManager keyManager = new KeyManager();
                KeyManager.createNewKeys(getBaseContext(), "authority2");
                keyManager.refreshKeys();

            }
                SessionStore      sessionStore      = new MySessionStore();
                PreKeyStore       preKeyStore       = new MyPreKeyStore();
                SignedPreKeyStore signedPreKeyStore = new MySignedPreKeyStore();
                IdentityKeyStore  identityStore     = new MyIdentityKeyStore();
            //}
        });*/
    }
    public void onClickTestBtn(View v){
        TLSInitiateKey keyInit=new TLSInitiateKey(getBaseContext());
        keyInit.setCallback(new TLSInitiateKey.Callback() {
            @Override
            public void onSuccess(){
                Log.d("HS","TLSSession before");
                TLSSession connTest=new TLSSession();
                Log.d("HS","성공!");
            }
            @Override
            public void onError(){

            }
        });
    }
    public void onClickTestBtn2(View v){
        xmpp.init("hosung","3437");
        xmpp.connectConnection();
        //xmpp.sendMsg();
    }
    public void onClickTestBtn3(View v){
        final HSSocketClient socketClient=new HSSocketClient("test.hodofactory.com",443);
        socketClient.setClientCallback(new HSSocketClient.ClientCallback(){
            @Override
            public void onConnect(Socket socket){
                Log.d("HS","onConnect");
                socketClient.send("sendsend");
                //TLSSession connTest=new TLSSession();
            }
            @Override
            public void onDisconnect(String message){
                Log.d("HS","연결 끝");
            }
            @Override
            public void onConnectError(Socket socket,String Message){
            }
            @Override
            public void onReceive(byte[] data){
                try{
                    Log.d("HS",new String(data,0,data.length));
                    SSLSocketFactory internalSSLSocketFactory;
                    SSLContext aa=new TLSBuild().createContext();
                    internalSSLSocketFactory=aa.getSocketFactory();
                    SSLSocket a=(SSLSocket)internalSSLSocketFactory.createSocket(socketClient.socket,"test.hodofactory.com",socketClient.socket.getPort(),true);
                    a.startHandshake();
                }catch(CertificateException e){}
                catch(UnrecoverableKeyException e){}
                catch(NoSuchAlgorithmException e){}
                catch(KeyStoreException e){}
                catch(KeyManagementException e){}
                catch(IOException e){}
            }
        });
        socketClient.connect();
    }
    public class MyTask extends HSTask<Integer, Integer, Integer> {
        @Override
        protected void onPreExecute() {
            //super.onPreExecute();
        }
        @Override
        protected Integer doInBackground(Integer... integers) {
            if(!Thread.currentThread().isInterrupted()){
                try{
                    for(int i=0;i<5&&check;i++){
                        Thread.sleep(1000);
                        Log.d("HS",integers[0]+"실행");
                    }
                }catch(InterruptedException e){}
                publishProgress(20);
                return 5;
            }
            return 0;
        }

        @Override
        protected void onProgressUpdate(Integer... params) {
            Log.d("MyAsyncTask", params[0] + " % ");
        }

        @Override
        protected void onPostExecute(Integer result) {
            super.onPostExecute(result);

            Log.d("HS", "result : " + result);
        }
        @Override
        protected void onCancelled(Integer result){
            Log.d("HS","Stop!!"+result);
        }
    }
}
