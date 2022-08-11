pragma circom 2.0.2;

include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/sha256/sha256.circom";

template commitment(k1, k2) {
    signal input voteCount;
    signal input eligibleRoot;
    signal input voterRoot;
    signal input msghash[k1];

    signal input negalfa1xbeta2[6][2][k2]; // e(-alfa1, beta2)
    signal input gamma2[2][2][k2];
    signal input delta2[2][2][k2];
    signal input IC[2][2][k2];

    signal output out;

    component hasher = Sha256((3 + k1 + 6 * 2 * k2 + 3 * 2 * 2 * k2) * 256);

    var hasherIdx = 0;

    component n2bVoteCount = Num2Bits(256);
    n2bVoteCount.in <== voteCount;
    for (var i = 0;i < 256;i++) {
        hasher.in[hasherIdx] <== n2bVoteCount.out[255 - i];
        hasherIdx++;
    }

    component n2bEligibleRoot = Num2Bits(256);
    n2bEligibleRoot.in <== eligibleRoot;
    for (var i = 0;i < 256;i++) {
        hasher.in[hasherIdx] <== n2bEligibleRoot.out[255 - i];
        hasherIdx++;
    }

    component n2bVoterRoot = Num2Bits(256);
    n2bVoterRoot.in <== voterRoot;
    for (var i = 0;i < 256;i++) {
        hasher.in[hasherIdx] <== n2bVoterRoot.out[255 - i];
        hasherIdx++;
    }

    component n2bMsghash[k1];
    for (var i = 0;i < k1;i++) {
        n2bMsghash[i] = Num2Bits(256);
        n2bMsghash[i].in <== msghash[i];
        for (var j = 0;j < 256;j++) {
            hasher.in[hasherIdx] <== n2bMsghash[i].out[255 - j];
            hasherIdx++;
        }
    }

    component n2bNegalfa1xbeta2[6][2][k2];
    for (var i = 0;i < 6;i++) {
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k2;idx++) {
                n2bNegalfa1xbeta2[i][j][idx] = Num2Bits(256);
                n2bNegalfa1xbeta2[i][j][idx].in <== negalfa1xbeta2[i][j][idx];
                for (var k = 0;k < 256;k++) {
                    hasher.in[hasherIdx] <== n2bNegalfa1xbeta2[i][j][idx].out[255 - k];
                    hasherIdx++;
                }
            }
        }
    }

    component n2bGamma2[2][2][k2];

    for (var i = 0;i < 2;i++) {
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k2;idx++) {
                n2bGamma2[i][j][idx] = Num2Bits(256);
                n2bGamma2[i][j][idx].in <== gamma2[i][j][idx];
                for (var k = 0;k < 256;k++) {
                    hasher.in[hasherIdx] <== n2bGamma2[i][j][idx].out[255 - k];
                    hasherIdx++;
                }
            }
        }
    }

    component n2bDelta2[2][2][k2];

    for (var i = 0;i < 2;i++) {
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k2;idx++) {
                n2bDelta2[i][j][idx] = Num2Bits(256);
                n2bDelta2[i][j][idx].in <== delta2[i][j][idx];
                for (var k = 0;k < 256;k++) {
                    hasher.in[hasherIdx] <== n2bDelta2[i][j][idx].out[255 - k];
                    hasherIdx++;
                }
            }
        }
    }

    component n2bIC[2][2][k2];

    for (var i = 0;i < 2;i++) {
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k2;idx++) {
                n2bIC[i][j][idx] = Num2Bits(256);
                n2bIC[i][j][idx].in <== IC[i][j][idx];
                for (var k = 0;k < 256;k++) {
                    hasher.in[hasherIdx] <== n2bIC[i][j][idx].out[255 - k];
                    hasherIdx++;
                }
            }
        }
    }

    component outb2n = Bits2Num(250);
    for (var i = 0;i < 250;i++) {
        outb2n.in[249 - i] <== hasher.out[i];
    }
    log(12347878);
    log(outb2n.out);
    out <== outb2n.out;
}
