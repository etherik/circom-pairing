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
    for (var i = 0;i < 160;i += 4) {
        chunks[i/4] = Bits2Num(4);
        for (var j = 0;j < 4;j++) {
            chunks[i/4].in[j] <== addressBits[i + j];
        }

        adder[i/4] = GreaterThan(4);
        adder[i/4].in[0] <== chunks[i/4].out;
        adder[i/4].in[1] <== 9;


        reChunks[i/4] = Num2Bits(8);
        reChunks[i/4].in <== chunks[i/4].out + 48 + (adder[i/4].out * 39);
        for (var j = 0;j < 8;j++) {
            moddedBits[(156-i)*2 + j] <== reChunks[i/4].out[j];
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
    for (var i = 0; i < 560 / 8; i += 1) {
      for (var j = 0; j < 8; j++) {
        // keck.in[8*i + j] <== reverse[8*i + (7-j)];
        keck.in[8*i + j] <== fullMsgBits[8*i + j];
      }
    }

    for (var i = 0;i < 256;i++) out[i] <== keck.out[i];
}
