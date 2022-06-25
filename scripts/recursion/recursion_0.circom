pragma circom 2.0.3;

template Example () {
    signal input a;
    signal input b;
    signal input c;
    
    c === a * b;
}

component main { public [ c ] } = Example();

/* INPUT = {
    "a": "5",
    "b": "77",
    "c": "385"
} */

// 3 zoom ins