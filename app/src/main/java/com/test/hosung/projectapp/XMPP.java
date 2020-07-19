package com.test.hosung.projectapp;

import android.os.AsyncTask;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import org.jivesoftware.smack.AbstractXMPPConnection;
import socket.xmpp.builder.ConnectionListener;

import org.jivesoftware.smack.SASLAuthentication;
import org.jivesoftware.smack.SmackException;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.XMPPException;
import org.jivesoftware.smack.chat.Chat;
import org.jivesoftware.smack.chat.ChatManager;
import org.jivesoftware.smack.packet.StreamOpen;
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration;
import org.jivesoftware.smack.util.TLSUtils;
import org.jivesoftware.smackx.iqregister.AccountManager;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import socket.ssl.TLSBuild;
import socket.xmpp.HSXMPPTCPConnection;
import socket.xmpp.builder.XMPPConnectionConfiguration;
import util.HSTask;

public class XMPP {
    private static final String DOMAIN = "test.hodofactory.com";
    private static final String HOST = "192.168.0.14";
    //private static final String HOST = "test.hodofactory.com";
    private static final int PORT = 5222;
    private String userName ="";
    private String passWord = "";
    HSXMPPTCPConnection connection;
    ChatManager chatmanager;
    Chat newChat;
    XMPPConnectionListener connectionListener = new XMPPConnectionListener();
    private boolean connected;
    private boolean isToasted;
    private boolean chat_created;
    private boolean loggedin;

    //Initialize
    public void init(String userId,String pwd){
        try{
            Log.i("XMPP", "Initializing!");
            this.userName = userId;
            this.passWord = pwd;
            XMPPConnectionConfiguration.Builder configBuilder = XMPPConnectionConfiguration.builder();
            configBuilder.setUsernameAndPassword(userName, passWord);
            //configBuilder.setSecurityMode(ConnectionConfiguration.SecurityMode.disabled);
            configBuilder.setSecurityMode(XMPPConnectionConfiguration.SecurityMode.required);
            configBuilder.setCustomSSLContext(new TLSBuild().createContext());
            configBuilder.setResource("Android");
            configBuilder.setServiceName(DOMAIN);
            configBuilder.setHost(HOST);
            configBuilder.setPort(PORT);

            //configBuilder.setDebuggerEnabled(true);
            //connection = new HSXMPPTCPConnection(TLSUtils.setTLSOnly(configBuilder).build());
            connection = new HSXMPPTCPConnection(configBuilder.build());
            connection.addConnectionListener(connectionListener);
        }catch(CertificateException e){}
        catch(UnrecoverableKeyException e){}
        catch(NoSuchAlgorithmException e){}
        catch(KeyStoreException e){}
        catch(KeyManagementException e){}
        catch(IOException e){}
    }

    // Disconnect Function
    public void disconnectConnection(){
        SASLAuthentication
        new Thread(new Runnable() {
            @Override
            public void run() {
                connection.disconnect();
            }
        }).start();
    }

    public void connectConnection() {
        HSTask<Void, Void, Boolean> connectionThread = new HSTask<Void, Void, Boolean>() {
            @Override
            protected Boolean doInBackground(Void... arg0) {
                //연결 시도
                try {
                    Log.d("HSTest","Connect!");
                    connection.connect();
                    AccountManager accountManager= AccountManager.getInstance(connection);
                    //login();
                    connected = true;
                } catch (IOException e) {
                } catch (SmackException e) {

                } catch (XMPPException e) {
                }

                return null;
            }
        };
        connectionThread.execute();
    }


    public void sendMsg() {
        if (connection.isConnected()== true) {
            // Assume we've created an XMPPConnection name "connection"._
            chatmanager = ChatManager.getInstanceFor(connection);
            newChat = chatmanager.createChat("concurer@nimbuzz.com");

            try {
                newChat.sendMessage("Howdy!");
            } catch (SmackException.NotConnectedException e) {
                e.printStackTrace();
            }
        }
    }

    public void login() {

        try {
            Log.d("HSTest","before login");
            connection.login(userName, passWord);
            Log.i("HSTest", "Yey! We're connected to the Xmpp server!");

        } catch (XMPPException | SmackException | IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
        }

    }



    //Connection Listener to check connection state
    public class XMPPConnectionListener implements ConnectionListener {
        @Override
        public void connected(final HSXMPPTCPConnection connection) {

            Log.d("xmpp", "Connected!");
            connected = true;
            if (!connection.isAuthenticated()) {
                login();
            }
        }

        @Override
        public void connectionClosed() {
            if (isToasted)

                new Handler(Looper.getMainLooper()).post(new Runnable() {

                    @Override
                    public void run() {
                        // TODO Auto-generated method stub


                    }
                });
            Log.d("xmpp", "ConnectionCLosed!");
            connected = false;
            chat_created = false;
            loggedin = false;
        }

        @Override
        public void connectionClosedOnError(Exception arg0) {
            if (isToasted)

                new Handler(Looper.getMainLooper()).post(new Runnable() {

                    @Override
                    public void run() {

                    }
                });
            Log.d("xmpp", "ConnectionClosedOn Error!");
            connected = false;

            chat_created = false;
            loggedin = false;
        }

        @Override
        public void reconnectingIn(int arg0) {

            Log.d("xmpp", "Reconnectingin " + arg0);

            loggedin = false;
        }

        @Override
        public void reconnectionFailed(Exception arg0) {
            if (isToasted)

                new Handler(Looper.getMainLooper()).post(new Runnable() {

                    @Override
                    public void run() {



                    }
                });
            Log.d("xmpp", "ReconnectionFailed!");
            connected = false;

            chat_created = false;
            loggedin = false;
        }

        @Override
        public void reconnectionSuccessful() {
            if (isToasted)

                new Handler(Looper.getMainLooper()).post(new Runnable() {

                    @Override
                    public void run() {
                        // TODO Auto-generated method stub



                    }
                });
            Log.d("xmpp", "ReconnectionSuccessful");
            connected = true;

            chat_created = false;
            loggedin = false;
        }

        @Override
        public void authenticated(HSXMPPTCPConnection arg0, boolean arg1) {
            Log.d("xmpp", "Authenticated!");
            loggedin = true;

            chat_created = false;
            new Thread(new Runnable() {

                @Override
                public void run() {
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }

                }
            }).start();
            if (isToasted)
                new Handler(Looper.getMainLooper()).post(new Runnable() {

                    @Override
                    public void run() {
                        // TODO Auto-generated method stub
                    }
                });
        }
    }
}
