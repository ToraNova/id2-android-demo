package com.toranova.id2;

import androidx.appcompat.app.AppCompatActivity;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.os.AsyncTask;
import android.os.Environment;
import android.provider.DocumentsContract;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.Button;
import android.widget.TextView;

import com.toranova.id2.R;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.Objects;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    private final String mTag = Constant.mTag;
    private static final int OPEN_USK = 2;
    private SharedPreferences pref;
    private SharedPreferences.Editor editor;
    private int cpar = 2;

    private VBLSProver prover;
    //deprecated, now import the params instead
    private String cparams[]  = new String[]{
        "assets/d192.param", // 0.2635ms; 0.02136ms; 0.2695ms
        "assets/d256.param", // 0.3529ms; 0.03157ms; 0.3502ms
        "assets/d359.param", // 0.7103ms; 0.05930ms; 0.7185ms
        "assets/d407.param", // 0.8678ms; 0.08130ms; 0.9269ms
        "assets/d522.param", // 1.522ms; 0.1323ms; 1.653ms
        "assets/d677.param", // 2.440ms; 0.2242ms; 2.717ms
        "assets/d1357.param" // 12.273ms; 0.9747ms; 14.91ms
    };

    private EditText idnt_in;
    private EditText host_in;
    private EditText port_in;
    private TextView res_out;
    private TextView key_out;
    private TextView key_file;
    private TextView par_out;
    private Button trigger;
    private byte[] uskbuf;

    @Override
    public void onClick(View view){
        switch (view.getId()) {
            case R.id.prove_button:
                // Do something
                ProveTask ptask = new ProveTask(idnt_in.getText().toString());
                ptask.execute(host_in.getText().toString(), port_in.getText().toString());
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        idnt_in = findViewById(R.id.uid_input);
        host_in = findViewById(R.id.host_input);
        port_in = findViewById(R.id.port_input);
        key_out = findViewById(R.id.dkey_view);
        key_file = findViewById(R.id.dkey_file);
        res_out = findViewById(R.id.result);
        par_out = findViewById(R.id.par_out);
        trigger = findViewById(R.id.prove_button);

        pref = getApplicationContext().getSharedPreferences(Constant.mPrf, MODE_PRIVATE);
        String tmp = pref.getString("uskb64", null);
        if(tmp == null){
        }else{
            byte[] hld = Base64.getDecoder().decode( tmp.getBytes() );
            uskbuf = new byte[hld.length+1];
            System.arraycopy(hld,0,uskbuf,0,hld.length);
            uskbuf[hld.length] = 0x00; //append final 00
            key_out.setText( tmp );
        }

        tmp = pref.getString("uskfilepath",null);
        if(tmp == null){
        }else{
            key_file.setText( tmp );
        }
        cpar = pref.getInt("paramidx",2);
        par_out.setText( cparams[cpar]);
        trigger.setOnClickListener(this);

    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch(item.getItemId()) {
        case R.id.key:
            //add the function to perform here
            //TODO: usk buffer from file
            // Request code for selecting a PDF document.
            openFile(Uri.fromFile( new File(Environment.getExternalStorageDirectory().getAbsolutePath())), OPEN_USK );
            return(true);

        case R.id.par:
            AlertDialog.Builder b = new AlertDialog.Builder(this);
            b.setTitle("Select Curve Parameters dn");
            String[] types = {"d192", "d256", "d359", "d407", "d522", "d677", "d1357"};
            b.setItems(types, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    dialog.dismiss();
                    cpar = which;
                    editor =  pref.edit();
                    editor.putInt("paramidx", cpar);
                    par_out.setText( cparams[cpar]);
                    editor.apply();
                }

            });
            b.show();
            return(true);
        }
        return(super.onOptionsItemSelected(item));
    }

    private void openFile(Uri pickerInitialUri, int request) {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");

        // Optionally, specify a URI for the file that should appear in the
        // system file picker when it loads.
        intent.putExtra(DocumentsContract.EXTRA_INITIAL_URI, pickerInitialUri);
        startActivityForResult(intent, request);
    }


    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {

        if (resultCode == Activity.RESULT_OK) {
            try {
                editor =  pref.edit();
            switch(requestCode){
                case OPEN_USK:
                    String uskb64 = readTextFromUri(data.getData());
                    editor.putString("uskb64", uskb64);  // Saving string
                    //uskbuf = Base64.getDecoder().decode( uskb64.getBytes("UTF-8"));
                    byte[] hld = Base64.getDecoder().decode( uskb64.getBytes() );
                    uskbuf = new byte[hld.length+1];
                    System.arraycopy(hld,0,uskbuf,0,hld.length);
                    uskbuf[hld.length] = 0x00; //append final 00
                    //Log.i(mTag,"Read USK base64: "+ uskb64 );
                    key_out.setText(uskb64);
                    key_file.setText( data.getData().getPath() );
                    editor.putString("uskfilepath", data.getData().getPath());
                    editor.apply();
                    break;
                default:
                    //TODO: handle err here
                    break;
            }

            }catch(Exception e){
                Log.e(mTag, "Exception caught:", e);
            }

        }
    }

    private String readTextFromUri(Uri uri) throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        try (InputStream inputStream =
                     getContentResolver().openInputStream(uri);
             BufferedReader reader = new BufferedReader(
                     new InputStreamReader(Objects.requireNonNull(inputStream)))) {
            String line;
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line);
            }
        }
        return stringBuilder.toString();
    }

    private class ProveTask extends AsyncTask<String,String,Integer> {

        String pid;

        //constructor, set aid to target identity
        protected ProveTask(String aid) {
            pid = aid;
                  }

        @Override
        protected Integer doInBackground(String... args) {

            //TODO: allow user to choose different params
            if(uskbuf == null){
                return 2;
            }

            try {
                publishProgress("PROVE Begins");
                prover = new VBLSProver( cparams[cpar], pid, uskbuf);

                byte[] rbuf = new byte[1024];
                byte[] hld, sendID;
                String hostname = args[0];
                int port = Integer.parseInt(args[1]);
                int rc;

                Log.i(mTag, "Connecting to " + hostname + ":" + port);
                publishProgress("Connecting to " + hostname + ":" + port);
                InetAddress serverAddr = InetAddress.getByName(hostname);

                //create a socket to make the connection with the server
                Socket socket = new Socket(serverAddr, port);

                //Opens a new writer to write to server
                //Opens a new reader to read messages from server
                //PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())), true);
                OutputStream out = socket.getOutputStream();
                //BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                InputStream in = socket.getInputStream();

                hld = pid.getBytes(Charset.forName("UTF-8"));
                sendID = new byte[hld.length+1]; //append c style string terminator
                System.arraycopy(hld,0,sendID,0,hld.length);
                sendID[hld.length] = 0x00;

                out.write(sendID);
                out.flush();
                Log.i(mTag, "Sent Ident:" + pid + "... Waiting for Go-Ahead (0x5A)");
                rc = in.read(rbuf, 0, 1); //wait for Go-Ahead 0x5A
                if (rbuf[0] != 0x5A) {
                    Log.e(mTag, "Failed to receive Go-Ahead (0x5A), ABORT");
                    out.close();
                    in.close();
                    return 1;
                }
                Log.i(mTag, "Received Go-Ahead (0x5A)");
                publishProgress("Received Go-Ahead (0x5A)");
                out.write(prover.getCommit());
                out.flush();
                publishProgress("Commit Sent...");
                Log.i(mTag,"Commit Sent..."+rc);
                rc = in.read(rbuf, 0, prover.getCHAlength());
                publishProgress("Challenge Received..."+rc);

                out.write(prover.getRSP(rbuf));
                out.flush();
                publishProgress("Response Sent...");
                Log.i(mTag,"Response Sent...");

                rbuf = new byte[1];
                rc =in.read(rbuf, 0, 1);
                out.close();
                in.close();
                if( rc < 1 || rbuf[0] != 0x00 ){
                    Log.i(mTag, "Identification Denied (!0x00)");
                    return 1;
                }
                Log.i(mTag, "Identification Success (0x00)");
                return 0;
            } catch( ConnectException e) {
                Log.e(mTag, "Verifier Server not Up!",e);
                return 3;

            }catch (Exception e) {
                Log.e(mTag, "Exception caught:", e);
            }
            return 1;

        }

        @Override
        protected void onProgressUpdate(String... status) {
            //display enabled, write to TextView or Toast
            res_out.setText(status[0]);
        }

        // required methods
        @Override
        protected void onPostExecute(Integer res) {
            switch( res.intValue()){
                case 0:
                    res_out.setText("ID Success 0x00");
                    break;
                case 1:
                    res_out.setText("Verify Fail 0x01");
                    break;
                case 2:
                    res_out.setText("No Key File Imported 0x02");
                    break;
                case 3:
                    res_out.setText("Verifier Not Online 0x03");
                    break;
                case 4:
                    res_out.setText("Params not configured 0x04");
                default:
                    res_out.setText("Unknown Error 0xFF");
                    break;
            }
        }
    }
}
