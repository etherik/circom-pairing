pragma circom 2.0.3;

include "../bn254/groth16.circom";
include "merkle.circom";
include "../../circom-ecdsa/circuits/ecdsa.circom";
include "../../circom-ecdsa/circuits/zk-identity/eth.circom";

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

    component hasher = MiMCSponge(3 + k1 + 6 * 2 * k2 + 3 * 2 * 2 * k2, 220, 1);
    hasher.k <== 123;

    hasher.ins[0] <== voteCount;
    hasher.ins[1] <== eligibleRoot;
    hasher.ins[2] <== voterRoot;
    var mimcIdx = 3;
    for (var i = 0;i < k1;i++) {
        hasher.ins[mimcIdx] <== msghash[i];
        mimcIdx++;
    }
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

    for (var i = 0;i < 2;i++) {
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k2;idx++) {
                hasher.ins[mimcIdx] <== IC[i][j][idx];
                mimcIdx++;
            }
        }
    } 
    out <== hasher.outs[0];
}

template Isokratia(levels) {
    // ecdsa fact
    var n1 = 64;
    var k1 = 4;

    // bn254 fact
    var k2 = 6;

    // one piece of the proof, the outermost shell
    signal input semiPublicCommitment;
    signal input voteCount;
    signal input eligibleRoot;
    signal input voterRoot;
    signal input r[k1];
    signal input s[k1];
    signal input msghash[k1];
    signal input pubkey[2][k1];
    signal input eligiblePathElements[levels];
    signal input voterPathElements[levels];
    signal input pathIndices[levels]; // note pathIndices are the same for both the eligibility and voter tree

    // inner verification key and proof
    // vk is semi public
    signal input negalfa1xbeta2[6][2][k2]; // e(-alfa1, beta2)
    signal input gamma2[2][2][k2];
    signal input delta2[2][2][k2];
    signal input IC[2][2][k2];
    signal input negpa[2][k2];
    signal input pb[2][2][k2];
    signal input pc[2][k2];


    // Check mimc of semi public inputs matches public commitment
    component computedCommitment = commitment(k1, k2);
    computedCommitment.voteCount <== voteCount;
    computedCommitment.eligibleRoot <== eligibleRoot;
    computedCommitment.voterRoot <== voterRoot;
    for (var i = 0;i < k1;i++) computedCommitment.msghash[i] <== msghash[i];
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
                computedCommitment.IC[i][j][idx] <== IC[i][j][idx];
            }
        }
    }

    semiPublicCommitment === computedCommitment.out;

    component correct = MultiAND(4);

    // Check signature verifies
    component sigVerify = ECDSAVerifyNoPubkeyCheck(n1, k1);
    for (var i = 0;i < k1;i++) {
        sigVerify.r[i] <== r[i];
        sigVerify.s[i] <== s[i];
        sigVerify.msghash[i] <== msghash[i];
        for (var j = 0;j < 2;j++) sigVerify.pubkey[j][i] <== pubkey[j][i];
    }

    correct.in[0] <== sigVerify.result;

    // Check pubkey in eligible merkle tree
    component eligible = VerifyAndModMembership(levels, n1, k1);
    eligible.root <== eligibleRoot;
    for (var i = 0;i < k1;i++) {
        for (var j = 0;j < 2;j++) eligible.pubkey[j][i] <== pubkey[j][i];
    }
    for (var i = 0;i < levels;i++) {
        eligible.pathElements[i] <== eligiblePathElements[i];
        eligible.pathIndices[i] <== pathIndices[i];
    }

    correct.in[1] <== eligible.valid;

    // Check pubkey in voter merkle tree, and get NULL-modded root
    component voters = VerifyAndModMembership(levels, n1, k1);
    voters.root <== voterRoot;
    for (var i = 0;i < k1;i++) {
        for (var j = 0;j < 2;j++) voters.pubkey[j][i] <== pubkey[j][i];
    }
    for (var i = 0;i < levels;i++) {
        voters.pathElements[i] <== voterPathElements[i];
        voters.pathIndices[i] <== pathIndices[i];
    }

    correct.in[2] <== voters.valid;

    // compute semiPublicCommitment for inner snark
    component innerCommitment = commitment(k1, k2);
    innerCommitment.voteCount <== voteCount - 1;
    innerCommitment.eligibleRoot <== eligibleRoot;
    innerCommitment.voterRoot <== voters.moddedRoot;
    for (var i = 0;i < k1;i++) innerCommitment.msghash[i] <== msghash[i];
    for (var i = 0;i < 6;i++) {
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k2;idx++) {
                innerCommitment.negalfa1xbeta2[i][j][idx] <== negalfa1xbeta2[i][j][idx];
            }
        }
    }
    for (var i = 0;i < 2;i++) {
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k2;idx++) {
                innerCommitment.gamma2[i][j][idx] <== gamma2[i][j][idx];
                innerCommitment.delta2[i][j][idx] <== delta2[i][j][idx];
                innerCommitment.IC[i][j][idx] <== IC[i][j][idx];
            }
        }
    }

    // check inner snark given commitment
    component groth16Verifier = verifyProof(1);
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
                groth16Verifier.IC[i][j][idx] <== IC[i][j][idx];
                groth16Verifier.pb[i][j][idx] <== pb[i][j][idx];                
            }
        }
    }

    for (var i = 0;i < 2;i++) {
        for (var idx = 0;idx < k2;idx++) {
            groth16Verifier.negpa[i][idx] <== negpa[i][idx];
            groth16Verifier.pc[i][idx] <== pc[i][idx];
        }
    }
    groth16Verifier.pubInput[0] <== innerCommitment.out;

    correct.in[3] <== groth16Verifier.out;

    component innermostORcorrect = OR();
    innermostORcorrect.a <== correct.out;
    component noVotes = IsEqual();
    noVotes.in[0] <== 1;
    noVotes.in[1] <== voteCount;
    innermostORcorrect.b <== noVotes.out;
    innermostORcorrect.out === 1;
}
