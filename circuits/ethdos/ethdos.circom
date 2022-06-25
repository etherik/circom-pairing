pragma circom 2.0.3;

include "../../node_modules/circomlib/circuits/mimcsponge.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../circom-ecdsa/circuits/ecdsa.circom";
include "../../circom-ecdsa/circuits/eth_addr.circom";
include "../bigint.circom";
include "./utils.circom";
include "../bn254/groth16.circom";

/*
SOURCE -> SINK, proof by SOURCE upto SINK

prove edge source->sink + snark of source

semi public - vk
public - degree, originator, address sink, semipublic commmitment 
private - proof upto source, sig of source saying "eth signed address sink", pubkey source
*/

template commitment(k2, pubInpCount) {    
    signal input negalfa1xbeta2[6][2][k2]; // e(-alfa1, beta2)
    signal input gamma2[2][2][k2];
    signal input delta2[2][2][k2];
    signal input IC[pubInpCount + 1][2][k2];

    signal output out;

    component hasher = MiMCSponge(6 * 2 * k2 + 2 * 2 * 2 * k2 + (pubInpCount + 1) * 2 * k2, 220, 1);
    hasher.k <== 123;

    var mimcIdx = 0;
    for (var i = 0;i < 6;i++) {
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k2;idx++) {
                hasher.ins[mimcIdx] <== negalfa1xbeta2[i][j][idx];
                mimcIdx++;
            }
        }
    }

    for (var i = 0;i < 2;i++) {
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k2;idx++) {
                hasher.ins[mimcIdx] <== gamma2[i][j][idx];
                mimcIdx++;
            }
        }
    }
    
    for (var i = 0;i < 2;i++) {
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k2;idx++) {
                hasher.ins[mimcIdx] <== delta2[i][j][idx];
                mimcIdx++;
            }
        }
    }

    for (var i = 0;i < pubInpCount + 1;i++) {
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k2;idx++) {
                hasher.ins[mimcIdx] <== IC[i][j][idx];
                mimcIdx++;
            }
        }
    } 
    out <== hasher.outs[0];
}

template sourceAddressAssembly(n, k) {
    signal input pubkey[2][k];
    signal output address;
    component flattenPub = FlattenPubkey(n, k);
    for (var i = 0; i < k; i++) {
        flattenPub.chunkedPubkey[0][i] <== pubkey[0][i];
        flattenPub.chunkedPubkey[1][i] <== pubkey[1][i];
    }

    component pubToAddr = PubkeyToAddress();
    for (var i = 0; i < 512; i++) {
        pubToAddr.pubkeyBits[i] <== flattenPub.pubkeyBits[i];
    }

    address <== pubToAddr.address;
}

template EthDos() {
    // this circuit fact
    var pubInpCount = 4;

    // ecdsa fact
    var n1 = 64;
    var k1 = 4;

    // bn254 fact
    var k2 = 6;

    // public
    signal input semiPublicCommitment;
    signal input degree;
    signal input originator;
    signal input sinkAddress;

    // private
    signal input r[k1];
    signal input s[k1];
    signal input sourcePubkey[2][k1];

    signal input negpa[2][k2];
    signal input pb[2][2][k2];
    signal input pc[2][k2];

    // inner verification key and proof
    // vk is semi public
    signal input negalfa1xbeta2[6][2][k2]; // e(-alfa1, beta2)
    signal input gamma2[2][2][k2];
    signal input delta2[2][2][k2];
    signal input IC[pubInpCount + 1][2][k2];


    // check commitment of vk
    component computedCommitment = commitment(k2, pubInpCount);
    for (var i = 0;i < 6;i++) {
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k2;idx++) {
                computedCommitment.negalfa1xbeta2[i][j][idx] <== negalfa1xbeta2[i][j][idx];
            }
        }
    }
    for (var i = 0;i < 2;i++) {
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k2;idx++) {
                computedCommitment.gamma2[i][j][idx] <== gamma2[i][j][idx];
                computedCommitment.delta2[i][j][idx] <== delta2[i][j][idx];
            }
        }
    }

    for (var i = 0;i < pubInpCount + 1;i++) {
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k2;idx++) {
                computedCommitment.IC[i][j][idx] <== IC[i][j][idx];
            }
        }
    }

    log(111);
    log(computedCommitment.out);

    semiPublicCommitment === computedCommitment.out;

    // ecdsa verify using msghash from other thing
    component msgHashBits = EthSignedAdressMessageHash();
    msgHashBits.address <== sinkAddress;
    log(11115);
    for (var i = 0;i < 256;i++) {
        log(msgHashBits.out[i]);
    }
    component msgHashBig = Bits2Big(n1, k1);
    for (var i = 0;i < 256;i++) msgHashBig.in[i] <== msgHashBits.out[i];

    log(112);
    for (var i = 0;i < k1;i++) {
        log(msgHashBig.out[i]);
    }
    

    component sigVerify = ECDSAVerifyNoPubkeyCheck(n1, k1);
    for (var i = 0;i < k1;i++) {
        sigVerify.r[i] <== r[i];
        sigVerify.s[i] <== s[i];
        sigVerify.msghash[i] <== msgHashBig.out[i];
        for (var j = 0;j < 2;j++) sigVerify.pubkey[j][i] <== sourcePubkey[j][i];
    }

    log(222);
    log(sigVerify.result);

    sigVerify.result === 1;

    // check recursive snark
    component groth16Verifier = verifyProof(pubInpCount);
    for (var i = 0;i < 6;i++) {
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k2;idx++) {
                groth16Verifier.negalfa1xbeta2[i][j][idx] <== negalfa1xbeta2[i][j][idx];
            }
        }
    }

    for (var i = 0;i < 2;i++) {
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k2;idx++) {
                groth16Verifier.gamma2[i][j][idx] <== gamma2[i][j][idx];
                groth16Verifier.delta2[i][j][idx] <== delta2[i][j][idx];
                groth16Verifier.pb[i][j][idx] <== pb[i][j][idx];                
            }
        }
    }

    for (var i = 0;i < pubInpCount + 1;i++) {
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k2;idx++) {
                groth16Verifier.IC[i][j][idx] <== IC[i][j][idx];
            }
        }
    }

    for (var i = 0;i < 2;i++) {
        for (var idx = 0;idx < k2;idx++) {
            groth16Verifier.negpa[i][idx] <== negpa[i][idx];
            groth16Verifier.pc[i][idx] <== pc[i][idx];
        }
    }

    groth16Verifier.pubInput[0] <== semiPublicCommitment;
    groth16Verifier.pubInput[1] <== degree - 1;
    groth16Verifier.pubInput[2] <== originator;

    component sourceAddress = sourceAddressAssembly(n1, k1);
    for (var i = 0;i < 2;i++) {
        for (var j = 0;j < k1;j++) sourceAddress.pubkey[i][j] <== sourcePubkey[i][j];
    }
    groth16Verifier.pubInput[3] <== sourceAddress.address;

    component innermost = IsEqual();
    innermost.in[0] <== degree;
    innermost.in[1] <== 1;

    log(333);
    log(innermost.out);

    component innermostORcorrect = OR();
    innermostORcorrect.a <== innermost.out;
    innermostORcorrect.b <== groth16Verifier.out;

    innermostORcorrect.out === 1;
}