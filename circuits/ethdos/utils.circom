pragma circom 2.0.3;

include "../../circom-ecdsa/circuits/vocdoni-keccak/keccak.circom";

template EthSignedAdressMessageHash() {
    signal input address;
    signal output out[256];

    component addressConverter = Num2Bits(160);
    addressConverter.in <== address;

    signal addressBits[160];

    for (var i = 0;i < 160;i++) addressBits[i] <== addressConverter.out[i];

    component prefix1Bits = Num2Bits(240);
    prefix1Bits.in <== 174416154161768351644703742350661337674511534951980036777361350784927060;

    component prefix2Bits = Num2Bits(120);
    prefix2Bits.in <== 375882444730857387225089211233218680;


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
            moddedBits[tmp] <== reChunks[i].out[7 - j];
        }
    }

    signal fullMsgBits[680];
    for (var i = 0;i < 240;i++) {
        fullMsgBits[i] <== prefix1Bits.out[239 - i];
    }
    for (var i = 0;i < 120;i++) {
        fullMsgBits[240 + i] <== prefix2Bits.out[119 - i];
    }
    for (var i = 0;i < 320;i++) {
        fullMsgBits[360 + i] <== moddedBits[i];
    }

    // for (var i = 0;i < 680;i++) out[i] <== fullMsgBits[i];

    // fullMsgBits matches preimage of ethers.utils
    // ethers.utils.concat(
	//	[ethers.utils.toUtf8Bytes(messagePrefix), 
	//	 ethers.utils.toUtf8Bytes(String(message.length)), 
	//	 ethers.utils.toUtf8Bytes(message)]);


    // signal reverse[680];
    // for (var i = 0; i < 680; i++) {
    //  reverse[i] <== fullMsgBits[679-i];
    // }

    component keck = Keccak(680, 256);
    for (var i = 0; i < 85; i++) {
      for (var j = 0; j < 8; j++) {
        keck.in[8*i + j] <== fullMsgBits[8*i + (7-j)];
        // keck.in[8*i + j] <== fullMsgBits[8*i + j];
      }
    }

    for (var i = 0;i < 32;i++) {
        for (var j = 0;j < 8;j++) {
            out[8*i + j] <== keck.out[8*i + (7-j)];
        }
    }
}