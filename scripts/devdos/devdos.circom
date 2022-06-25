pragma circom 2.0.3;

include "../../circuits/ethdos/ethdos.circom";

component main { public [semiPublicCommitment, degree, originator, sinkAddress] } = EthDos();
