package com.toranova.id2;

import android.util.Log;
import android.widget.TextView;

import com.toranova.id2.Constant;

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

    private final String mTag = Constant.mTag;

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
        StringBuilder sb;
        int rc, g1x;
        mPair = Id2_pairing.getPairing(param);
        //initialize fields
        G1 = mPair.getG1();
        G2 = mPair.getG2();
        Zr = mPair.getZr();

        Log.i(mTag, "cparam: G1/2/Zr SZ:"+ G1.getLengthInBytes() + "/" + G2.getLengthInBytes() + "/" + Zr.getLengthInBytes());
        //append a 00 onto aid buffer to match
        byte[] hld = aid.getBytes();
        byte[] idbuf = new byte[hld.length+1];
        System.arraycopy(hld,0,idbuf,0,hld.length);
        idbuf[hld.length] = 0x00; //null terminator C-style strings

        //initialize elements
        CMT = G1.newElement();
        CHA = Zr.newElement();
        me_Rbit = Zr.newElement();
        RSP = G1.newElement();
        me_Usk = (Point) G1.newElement();
        me_X2 = (Point) G1.newElement();
        me_hash = G1.newElementFromHash( idbuf,0, idbuf.length );

        /*
        byte[] fixedT = {
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        me_nonce = Zr.newElementFromBytes(fixedT);
        */

        me_nonce = Zr.newRandomElement(); //obtain nonce t


        //me_hash = G1.newElement().setFromHash( aid.getBytes(Charset.forName("UTF-8")), 0, aid.length());

        //MATCHED : me_hash me_Rbit
        //TODO: me_Usk, me_X2

        /*
        sb = new StringBuilder();
        sb.append("[");
        for (byte b : me_hash.toBytes()) {
            sb.append(String.format("%02X", b));
        }
        sb.append("]");
        Log.d(mTag, sb.toString());
        */

        g1x = G1.getLengthInBytes()/2;
        rbit_byte = usk[g1x+1];
        me_Rbit.set( rbit_byte ); //obtain the rbit

        Log.d(mTag,"usk-sz:"+usk.length+" g1X-sz:"+g1x);
        //me_Usk.setFromBytes( usk , 0 );
        rc = me_Usk.setFromBytesCompressed( usk, 0);
        Log.d(mTag,"usk-frombytes:"+rc);
        //me_X2.setFromBytes( usk , G1.getLengthInBytes()/2+1);
        rc = me_X2.setFromBytesCompressed( usk, g1x+2);
        Log.d(mTag,"X2-frombytes:"+rc);

        //confirming Rbit is correct
        Log.d(mTag, "rbit:"+ me_Rbit.toBigInteger().toString());
        //unable to convert usk, hash, x2 to int as they have x,y coord

        /*
        sb = new StringBuilder();
        sb.append("[");
        for (byte b : me_Usk.toBytesCompressed()) {
            sb.append(String.format("%02X", b));
        }
        sb.append(",\n");
        for (byte b : me_X2.toBytesCompressed()) {
            sb.append(String.format("%02X", b));
        }
        sb.append("]");
        Log.d(mTag, sb.toString());
         */

    }

    //obtain response from challenge
    public byte[] getRSP(byte [] chabuf){
        CHA = Zr.newElementFromBytes(chabuf);
        Log.d(mTag,"Received CHA:"+CHA.toBigInteger().toString());
        me_nonce = me_nonce.add(CHA);
        RSP = me_Usk.powZn(me_nonce);
        Point sendRSP;
        sendRSP = (Point) RSP;
        //return bytesToChars( RSP.toBytes() );
        return sendRSP.toBytesCompressed();
    }

    public int getCHAlength(){
        return Zr.getLengthInBytes();
    }

    public byte[] getCommit(){

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
        System.arraycopy(hld,0,out,0,clen);
        out[clen] = rbit_byte;
        Log.d(mTag, "Last CMT byte (RBIT) @ pos "+clen+" : "+ out[clen]);
        //return bytesToChars( out );
        return out;
    }

}
