pragma circom 2.0.3;

include "../../circuits/isokratia/isokratia.circom";

component main { public [semiPublicCommitment, degree, originator, sinkAddress] } = Isokratia(5);
