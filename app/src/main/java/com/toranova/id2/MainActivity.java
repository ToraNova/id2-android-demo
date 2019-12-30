package com.toranova.id2;

import androidx.appcompat.app.AppCompatActivity;

import android.app.Activity;
import android.content.Intent;
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
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.Objects;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    private final String mTag = "MainActivity";
    private static final int OPEN_FILE = 2;

    private VBLSProver prover;
    private String cparams[]  = new String[]{
            "assets/param160.properties",
            "assets/param224.properties",
            "assets/param256.properties"
    };


    private EditText idnt_in;
    private EditText host_in;
    private EditText port_in;
    private TextView res_out;
    private TextView key_out;
    private TextView key_file;
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
        Log.w( Constant.debugTag, "onCreate: ");
        setContentView(R.layout.activity_main);

        idnt_in = findViewById(R.id.uid_input);
        host_in = findViewById(R.id.host_input);
        port_in = findViewById(R.id.port_input);
        key_out = findViewById(R.id.dkey_view);
        key_file = findViewById(R.id.dkey_file);
        res_out = findViewById(R.id.result);
        trigger = findViewById(R.id.prove_button);

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
        case R.id.imp:
            //add the function to perform here
            //TODO: usk buffer from file
            // Request code for selecting a PDF document.
            openFile(Uri.fromFile( new File(Environment.getExternalStorageDirectory().getAbsolutePath())) );
            return(true);
        }
        return(super.onOptionsItemSelected(item));
    }

    private void openFile(Uri pickerInitialUri) {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");

        // Optionally, specify a URI for the file that should appear in the
        // system file picker when it loads.
        intent.putExtra(DocumentsContract.EXTRA_INITIAL_URI, pickerInitialUri);
        startActivityForResult(intent, OPEN_FILE);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {

        if (resultCode == Activity.RESULT_OK) {

            try {
                String uskb64 = readTextFromUri(data.getData());
                //uskbuf = Base64.getDecoder().decode( uskb64.getBytes("UTF-8"));
                uskbuf = Base64.getDecoder().decode( uskb64.getBytes());
                Log.i(mTag,"Read USK base64: "+ uskb64 );
                key_out.setText(uskb64);
                key_file.setText( data.getData().getPath() );
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
            prover = new VBLSProver(cparams[2], pid, uskbuf);

            char[] rbuf = new char[1024];
            String hostname = args[0];
            int port = Integer.parseInt(args[1]);

            try {
                int rc;
                Log.i(mTag, "Connecting to " + hostname + ":" + port);
                InetAddress serverAddr = InetAddress.getByName(hostname);

                //create a socket to make the connection with the server
                Socket socket = new Socket(serverAddr, port);

                //Opens a new writer to write to server
                //Opens a new reader to read messages from server
                //PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())), true);
                OutputStream out = socket.getOutputStream();
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                out.write(pid.getBytes(Charset.forName("UTF-8")));
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
                publishProgress("Received Go-Ahead (0x5A)"+rc);
                out.write(prover.getCommit());
                out.flush();
                publishProgress("Commit Sent..."+rc);
                rc = in.read(rbuf, 0, prover.getCHAlength());
                publishProgress("Challenge Received...");

                out.write(prover.getRSP(rbuf));
                out.flush();
                publishProgress("Response Sent..."+rc);

                rbuf = new char[1];
                rc =in.read(rbuf, 0, 1);
                Log.d(mTag, rbuf.toString());
                out.close();
                in.close();
                return Integer.parseInt(rbuf.toString());
            } catch (Exception e) {
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
            if (res.intValue() == 0) {
                res_out.setText("Success");
            } else {
                res_out.setText("Fail");
            }
        }
    }
}
