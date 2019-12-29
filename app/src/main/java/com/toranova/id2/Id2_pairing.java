package com.toranova.id2;

import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/*
This is the pairing class file for id2
IBI android library, this simple file handles pairing
gen from the string: based on example from jpbc

uses android pbc from (JPBC)
it.unisa.dia.gas.jpbc.android
http://gas.dia.unisa.it/projects/jpbc/docs/android.html

toranova.online
chia_jason96@live.com
 */
public class Id2_pairing {

    public static Pairing getPairing(String curve) {
        return PairingFactory.getPairing(getParameters(curve));
    }

    public static PairingParameters getParameters(String curve) {
        return PairingFactory.getInstance().loadParameters(curve);
    }

}
