pragma circom 2.0.3;

include "../../circom-ecdsa/circuits/vocdoni-keccak/keccak.circom";

template EthSignedAdressMessageHash() {
    signal input address;
    signal output out[256];

    component addressConverter = Num2Bits(160);
    addressConverter.in <== address;

    signal addressBits[160];

    for (var i = 0;i < 160;i++) addressBits[i] <== addressConverter.out[i];

    component prefixBits = Num2Bits(240);
    prefixBits.in <== 829508926077469496995265318093206896209766079988389694804882883725247769;

    signal moddedBits[320];
    component chunks[40];
    component adder[40];
    component reChunks[40];
    for (var i = 0;i < 40;i++) {
        chunks[i] = Bits2Num(4);
        for (var j = 0;j < 4;j++) {
            chunks[i].in[j] <== addressBits[i*4 + j];
        }

        adder[i] = GreaterThan(4);
        adder[i].in[0] <== chunks[i].out;
        adder[i].in[1] <== 9;


        reChunks[i] = Num2Bits(8);
        reChunks[i].in <== chunks[i].out + 48 + (adder[i].out * 39);
        for (var j = 0;j < 8;j++) {
            var tmp = (156-i*4)*2 + j;
            moddedBits[tmp] <== reChunks[i].out[j];
        }
    }

    signal fullMsgBits[560];
    for (var i = 0;i < 240;i++) {
        fullMsgBits[i] <== prefixBits.out[i];
    }
    for (var i = 0;i < 320;i++) {
        fullMsgBits[240 + i] <== moddedBits[i];
    }


    //signal reverse[560];
    //for (var i = 0; i < 560; i++) {
    //  reverse[i] <== fullMsgBits[559-i];
    //}

    component keck = Keccak(560, 256);
    for (var i = 0; i < 70; i++) {
      for (var j = 0; j < 8; j++) {
        // keck.in[8*i + j] <== reverse[8*i + (7-j)];
        keck.in[8*i + j] <== fullMsgBits[8*i + j];
      }
    }

    for (var i = 0;i < 256;i++) out[i] <== keck.out[i];
}
