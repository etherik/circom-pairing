pragma circom 2.0.3;

// include "circomlib/poseidon.circom";
// include "https://github.com/0xPARC/circom-secp256k1/blob/master/circuits/bigint.circom";

template Example () {
    signal input a;
    signal input b;
    signal input c;
    signal input d;
    signal input e;
    
    c === a * b;

    assert(a > 2);
    
    e === d*c;
}

component main { public [ a, b, d, e ] } = Example();