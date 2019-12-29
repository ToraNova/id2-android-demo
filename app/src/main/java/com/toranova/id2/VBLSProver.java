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
    private byte[] mUsk;

    private Element me_Usk;
    private Element me_Rbit;
    private Element me_nonce;
    private Element me_hash;
    private Element me_X2;
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
        mPair = Id2_pairing.getPairing(param);
        //initialize fields
        G1 = mPair.getG1();
        G2 = mPair.getG2();
        Zr = mPair.getZr();

        //initialize elements
        CMT = G1.newElement();
        CHA = Zr.newElement();
        me_Rbit = Zr.newElement();
        RSP = G1.newElement();
        me_Usk = G1.newElement();
        me_X2 = G1.newElement();
        me_hash = G1.newElementFromHash(aid.getBytes(Charset.forName("UTF-8")),0,aid.length());
        me_nonce = Zr.newRandomElement(); //obtain nonce t
        mUsk = usk;
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
    public char[] getRSP(char [] chabuf){
        CHA = Zr.newElementFromBytes(charsToBytes(chabuf));
        RSP = me_nonce.add(CHA);
        RSP = me_Usk.powZn(RSP);
        return bytesToChars( RSP.toBytes() );
    }

    public int getCHAlength(){
        return Zr.getLengthInBytes();
    }

    public char[] getCommit(){

        CMT = me_X2.powZn(me_Rbit);
        CMT = CMT.mul(me_hash);
        CMT = me_X2.powZn(me_nonce);
        return bytesToChars( CMT.toBytes() );
    }

}
