pragma circom 2.0.2;

include "../../node_modules/circomlib/circuits/mimcsponge.circom";

// Computes MiMC([left, right])
template HashLeftRight() {
    signal input left;
    signal input right;
    signal output hash;

    component hasher = MiMCSponge(2, 220, 1);
    hasher.ins[0] <== left;
    hasher.ins[1] <== right;
    hasher.k <== 123;
    hash <== hasher.outs[0];
}

// if s == 0 returns [in[0], in[1]]
// if s == 1 returns [in[1], in[0]]
template DualMux() {
    signal input in[2];
    signal input s;
    signal output out[2];

    s * (1 - s) === 0;
    out[0] <== (in[1] - in[0])*s + in[0];
    out[1] <== (in[0] - in[1])*s + in[1];
}

// Verifies that merkle proof is correct for given merkle root and a leaf
// pathIndices input is an array of 0/1 selectors telling whether given pathElement is on the left or right side of merkle path
template MerkleCheckAndMod(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    signal output valid;
    signal output moddedRoot;

    component selectors[levels];
    component hashers[levels];

    for (var i = 0; i < levels; i++) {
        selectors[i] = DualMux();
        selectors[i].in[0] <== i == 0 ? leaf : hashers[i - 1].hash;
        selectors[i].in[1] <== pathElements[i];
        selectors[i].s <== pathIndices[i];

        hashers[i] = HashLeftRight();
        hashers[i].left <== selectors[i].out[0];
        hashers[i].right <== selectors[i].out[1];
    }

    component checker = IsEqual();
    checker.in[0] <== root;
    checker.in[1] <== hashers[levels - 1].hash;
    valid <== checker.out;

    component moddedSelectors[levels];
    component moddedHashers[levels];

    for (var i = 0; i < levels; i++) {
        moddedSelectors[i] = DualMux();
        moddedSelectors[i].in[0] <== i == 0 ? 0 : moddedHashers[i - 1].hash;
        moddedSelectors[i].in[1] <== pathElements[i];
        moddedSelectors[i].s <== pathIndices[i];

        moddedHashers[i] = HashLeftRight();
        moddedHashers[i].left <== moddedSelectors[i].out[0];
        moddedHashers[i].right <== moddedSelectors[i].out[1];
    }

    moddedRoot <== moddedHashers[levels - 1].hash;
}

// Verify mimc(address(pubkey)) is in the merkle tree and return modded tree without the value if it is
// levels is the number of Levels in merkle tree, n is the number of bits per each of the k registers
template VerifyAndModMembership(levels, n, k) {
    signal input root;
    signal input pubkey[2][k];
    signal input pathElements[levels];
    signal input pathIndices[levels];

    signal output valid;
    signal output moddedRoot;

    component flattenPub = FlattenPubkey(n, k);
    for (var i = 0; i < k; i++) {
        flattenPub.chunkedPubkey[0][i] <== pubkey[0][i];
        flattenPub.chunkedPubkey[1][i] <== pubkey[1][i];
    }

    component addressGen = PubkeyToAddress();
    for (var i = 0;i < 512;i++) addressGen.pubkeyBits[i] <== flattenPub.pubkeyBits[i];
    log(addressGen.address);

    component addressMimc = MiMCSponge(1, 220, 1);
    addressMimc.ins[0] <== addressGen.address;
    addressMimc.k <== 123;

    log(addressMimc.outs[0]);

    component merkleCheck = MerkleCheckAndMod(levels);
    merkleCheck.leaf <== addressMimc.outs[0];
    merkleCheck.root <== root;
    for (var i = 0; i < levels; i++) {
        merkleCheck.pathElements[i] <== pathElements[i];
        merkleCheck.pathIndices[i] <== pathIndices[i];
    }

    valid <== merkleCheck.valid;
    moddedRoot <== merkleCheck.moddedRoot;
}