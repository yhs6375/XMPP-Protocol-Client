package socket;

import android.util.Log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;

import util.HSTask;

public class HSSocketClient {
    public Socket socket;
    private OutputStream socketOutput;
    private InputStream socketInput;
    private int port;
    private ClientCallback listener=null;
    private String ip;
    HSTask connectTask;
    HSTask receiveTask;
    public HSSocketClient(String ip, int port){
        this.ip=ip;
        this.port=port;
    }
    public void connect(){
        Log.d("HS",Thread.currentThread().getName());
        connectTask=new ConnectTask();
        connectTask.execute();
    }
    private void T_connect(){
        socket=new Socket();
        InetSocketAddress socketAddress=new InetSocketAddress(ip,port);
        try{
            socket.connect(socketAddress,3000);
            socketOutput=socket.getOutputStream();
            socketInput=socket.getInputStream();
            receiveTask=new ReceiveTask();
            receiveTask.execute();

            Log.d("HS","connect success");
            if(listener!=null){
                listener.onConnect(socket);
            }
        }catch(IOException e){
            if(listener!=null){
                listener.onConnectError(socket,e.getMessage());
            }
            Log.d("HS",e.getMessage());
        }
    }
    public void disconnect(){
        try{
            socket.close();
            connectTask.cancel();
            receiveTask.cancel();
        }catch(IOException e){
            if(listener!=null){
                listener.onDisconnect(e.getMessage());
            }
        }
    }
    public void send(String message){
        try{
            socketOutput.write(message.getBytes());
            Log.d("HSTest","Send Success");
        }catch(IOException e){
            listener.onDisconnect(e.getMessage());
        }
    }
    public void send(byte[] message){
        try{
            socketOutput.write(message);
            Log.d("HSTest","Send Success");
        }catch(IOException e){
            listener.onDisconnect(e.getMessage());
        }
    }
    public void setClientCallback(ClientCallback listener){
        this.listener=listener;
    }
    public interface ClientCallback{
        void onConnect(Socket socket);
        void onReceive(byte[] message);
        void onDisconnect(String message);
        void onConnectError(Socket socket,String Message);
    }
    private class ConnectTask extends HSTask<Integer,Integer,Integer> {
        @Override
        protected Integer doInBackground(Integer... integers) {
            T_connect();
            return null;
        }
        @Override
        protected void onProgressUpdate(Integer... params) {

        }
        @Override
        protected void onPostExecute(Integer result) {

        }
        @Override
        protected void onCancelled(Integer result){

        }
    }
    private class ReceiveTask extends HSTask<Integer,Integer,Integer>{
        @Override
        protected Integer doInBackground(Integer... integers){
            byte[] data=new byte[2048];
            data[0]=38;
            int len;
            try{
                while((len=socketInput.read(data))!=-1){
                    byte[] temp=new byte[len];
                    System.arraycopy(data,0,temp,0,len);
                    listener.onReceive(temp);
                }
            }catch(IOException e){;}
            catch(NullPointerException e){
            }
            return null;
        }

    }
}