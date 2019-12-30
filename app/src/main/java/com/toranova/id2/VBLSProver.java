package com.toranova.id2;

import android.util.Log;
import android.widget.TextView;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Point;

/*

This is a prover using VBLS for the id2 library
It uses JPBC, a java port of the pbc library by
Ben Lyn

it.unisa.dia.gas.jpbc.android
http://gas.dia.unisa.it/projects/jpbc/docs/android.html

 */

public class VBLSProver {

    private final String mTag = "toranova.id2.VBLSProver";

    private Pairing mPair;
    private byte rbit_byte;

    private Point me_Usk;
    private Point me_X2;
    //private Element me_Usk;
    //private Element me_X2;
    private Element me_Rbit;
    private Element me_nonce;
    private Element me_hash;
    private Element CHA;
    private Element CMT;
    private Element RSP;

    private Field G1;
    private Field G2;
    private Field Zr;

    private TextView mTView = null;

    public void setDisplay(TextView v){
        mTView = v;
    }

    //constructor for the vbls prover
    // ident - user signed identity
    // usk - user's secret
    // param - curve params
    public VBLSProver(String param, String aid, byte[] usk){
        int rc, g1x;
        mPair = Id2_pairing.getPairing(param);
        //initialize fields
        G1 = mPair.getG1();
        G2 = mPair.getG2();
        Zr = mPair.getZr();

        Log.i(mTag, "cparam: G1/2/Zr SZ:"+ G1.getLengthInBytes() + "/" + G2.getLengthInBytes() + "/" + Zr.getLengthInBytes());

        //initialize elements
        CMT = G1.newElement();
        CHA = Zr.newElement();
        me_Rbit = Zr.newElement();
        RSP = G1.newElement();
        me_Usk = (Point) G1.newElement();
        me_X2 = (Point) G1.newElement();
        //me_hash = G1.newElementFromHash(aid.getBytes(Charset.forName("UTF-8")),0,aid.length());
        me_nonce = Zr.newRandomElement(); //obtain nonce t
        me_hash = G1.newElement().setFromHash( aid.getBytes(Charset.forName("UTF-8")), 0, aid.length());

        g1x = G1.getLengthInBytes()/2;
        rbit_byte = usk[g1x];
        me_Rbit.set( rbit_byte ); //obtain the rbit

        Log.d(mTag,"usk-sz:"+usk.length+" g1X-sz:"+g1x);
        //me_Usk.setFromBytes( usk , 0 );
        rc = me_Usk.setFromBytesCompressed( usk, 0);
        Log.d(mTag,"usk-frombytes:"+rc);
        //me_X2.setFromBytes( usk , G1.getLengthInBytes()/2+1);
        rc = me_X2.setFromBytesCompressed( usk, g1x);
        Log.d(mTag,"X2-frombytes:"+rc);

        //confirming Rbit is correct
        Log.d(mTag, "rbit:"+ me_Rbit.toBigInteger().toString());
        //unable to convert usk, hash, x2 to int as they have x,y coord

        /*
        StringBuilder sb = new StringBuilder();
        sb.append("[ ");
        for (byte b : usk) {
            sb.append(String.format("0x%02X ", b));
        }
        sb.append("]");
        Log.d(mTag, sb.toString());
         */

    }

    public byte[] charsToBytes(char[] chars){
        Charset charset = Charset.forName("UTF-8");
        ByteBuffer byteBuffer = charset.encode(CharBuffer.wrap(chars));
        return Arrays.copyOf(byteBuffer.array(), byteBuffer.limit());
    }

    public char[] bytesToChars(byte[] bytes){
        Charset charset = Charset.forName("UTF-8");
        CharBuffer charBuffer = charset.decode(ByteBuffer.wrap(bytes));
        return Arrays.copyOf(charBuffer.array(), charBuffer.limit());
    }

    //obtain response from challenge
    public byte[] getRSP(char [] chabuf){
        CHA = Zr.newElementFromBytes(charsToBytes(chabuf));
        RSP = me_nonce.add(CHA);
        RSP = me_Usk.powZn(RSP);
        //return bytesToChars( RSP.toBytes() );
        return RSP.toBytes();
    }

    public int getCHAlength(){
        return Zr.getLengthInBytes();
    }

    public byte[] getCommit(){

        /*
        StringBuilder sb = new StringBuilder();
        sb.append("[ ");
        for (byte b : me_hash.toBytes()) {
            sb.append(String.format("0x%02X ", b));
        }
        sb.append("]");
        Log.d(mTag, sb.toString());
         */

        //Log.d(mTag, "HASH:"+me_hash.toBigInteger().toString());
        //Log.d(mTag, "X2:"+me_X2.toBigInteger().toString());
        //Log.d(mTag, "RB:"+me_Rbit.toBigInteger().toString());


        CMT = me_X2.powZn(me_Rbit);
        CMT = CMT.mul(me_hash);
        CMT = me_X2.powZn(me_nonce);
        Point sendCMT = (Point) CMT;
        int clen = sendCMT.getLengthInBytesCompressed();
        byte[] out = new byte[clen+1];
        byte[] hld = sendCMT.toBytesCompressed();
        for( int i=0;i<hld.length;i++){
            out[i] = hld[i];
        }
        out[clen] = rbit_byte;
        Log.d(mTag, "Last CMT byte (RBIT) @ pos "+clen+" : "+ out[clen]);
        //return bytesToChars( out );
        return out;
    }

}
