pragma circom 2.0.3;

include "../../circuits/isokratia/isokratia.circom";

component main { public [semiPublicCommitment] } = Isokratia(5);
