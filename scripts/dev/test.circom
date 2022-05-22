pragma circom 2.0.3;

include "../../circuits/curve.circom";
include "../../circuits/pairing.circom";
include "../../circuits/bls12_381_hash_to_G2.circom";

// Curve E : y^2 = x^3 + b
// Inputs:
//  in is 2 x k array where P = (x, y) is a point in E(Fp) 
//  inIsInfinity = 1 if P = O, else = 0
// Output:
//  out = [x]P is 2 x k array representing a point in E(Fp)
//  isInfinity = 1 if [x]P = O, else = 0
// Assume:
//  x in [0, 2^385) 
//  `in` is point in E even if inIsInfinity = 1 just so nothing goes wrong
//  E(Fp) has no points of order 2
template MyEllipticCurveScalarMultiply(n, k, b, p){
    signal input in[2][k];
    signal input inIsInfinity;
    signal input x[k];

    signal output out[2][k];
    signal output isInfinity;
        
    var BitLength = n*k;
    component Bits = BigToBits(n, k);
    for (var i = 0;i < k;i++) Bits.in[i] <== x[i];

    signal R[BitLength + 1][2][k]; 
    signal R_isO[BitLength + 1];
    signal addendum[BitLength][2][k];
    component Pdouble[BitLength];
    component Padd[BitLength];

    // if in = O then [x]O = O so there's no point to any of this
    signal P[2][k];
    for(var j=0; j<2; j++)for(var idx=0; idx<k; idx++)
        P[j][idx] <== in[j][idx];

    for (var j = 0;j < 2;j++) {
        for (var idx = 0;idx < k;idx++) {
            R[BitLength][j][idx] <== P[j][idx];
        }
    }
    R_isO[BitLength] <== 1;

    for (var i = BitLength - 1;i >= 0;i--) {
        // E(Fp) has no points of order 2, so the only way 2*R[i+1] = O is if R[i+1] = O 
        Pdouble[i] = EllipticCurveDouble(n, k, 0, b, p);  
        for(var j=0; j<2; j++)for(var idx=0; idx<k; idx++)
            Pdouble[i].in[j][idx] <== R[i+1][j][idx]; 
        
        // Padd[curid] = Pdouble[i] + P if bits[i].out == 1
        // Padd[curid] = Pdouble[i] if bits[i].out == 0

        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k;idx++) {
                addendum[i][j][idx] <== Bits.out[i]*P[j][idx];
            }
        }

        Padd[i] = EllipticCurveAdd(n, k, 0, b, p);
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k;idx++) {
                Padd[i].a[j][idx] <== Pdouble[i].out[j][idx]; 
                Padd[i].b[j][idx] <== addendum[i][j][idx];
            }
        }
        Padd[i].aIsInfinity <== R_isO[i+1];
        Padd[i].bIsInfinity <== 1 - Bits.out[i];

        R_isO[i] <== Padd[i].isInfinity; 
        for(var j=0; j<2; j++)for(var idx=0; idx<k; idx++)
            R[i][j][idx] <== Padd[i].out[j][idx];
    }

    // output = O if input = O or R[0] = O 
    isInfinity <== inIsInfinity + R_isO[0] - inIsInfinity * R_isO[0];
    for(var i=0; i<2; i++)for(var idx=0; idx<k; idx++)
        out[i][idx] <== R[0][i][idx] + isInfinity * (in[i][idx] - R[0][i][idx]);
}

template verifyProof(n, k, publicInputCount) {
    // BLS12-381 facts
    var p[50] = get_BLS12_381_prime(n, k);
    var b = 4;

    // verification key
    signal input alfa1xbeta2[6][2][k]; // e(alfa1, beta2)
    signal input gamma2[2][2][k];
    signal input delta2[2][2][k];
    signal input IC[publicInputCount+1][2][k];

    // proof
    signal input pa[2][k];
    signal input pb[2][2][k];
    signal input pc[2][k];
    signal input pubInput[publicInputCount][k];

    signal output out;

    // todo: probably dont need to check this inside snark if verifier
    // has these exposed as public input/a commitment of these exposed,
    // same with pubInput constraint checks
    component paInG1 = SubgroupCheckG1(n, k);
    component pbInG2 = SubgroupCheckG2(n, k);
    component pcInG1 = SubgroupCheckG1(n, k);

    for (var i = 0;i < 2;i++) {
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k;idx++) {
                pbInG2.in[i][j][idx] <== pb[i][j][idx];
            }
        }

        for (var idx = 0;idx < k;idx++) {
            paInG1.in[i][idx] <== pa[i][idx];
            pcInG1.in[i][idx] <== pc[i][idx];
        }
    }

    component lt[publicInputCount];
    for (var i = 0;i < publicInputCount;i++) {
        lt[i] = BigLessThan(n, k);
        for (var idx = 0;idx < k;idx++) {
            lt[i].a[idx] <== pubInput[i][idx];
            lt[i].b[idx] <== p[idx];
        }
    }
    for (var i = 0;i < publicInputCount;i++) {
        lt[i].out === 1;
    }


    component ICmultInp[publicInputCount];
    component ICPrefAddInp[publicInputCount];

    for (var i = 0;i < publicInputCount;i++) {
        ICmultInp[i] = MyEllipticCurveScalarMultiply(n, k, b, p);
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k;idx++) ICmultInp[i].in[j][idx] <== IC[i + 1][j][idx];
        }
        ICmultInp[i].inIsInfinity <== 0;
        for (var idx = 0;idx < k;idx++) ICmultInp[i].x[idx] <== pubInput[i][idx];

        ICPrefAddInp[i] = EllipticCurveAdd(n, k, 0, b, p);
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k;idx++) {
                ICPrefAddInp[i].a[j][idx] <== ICmultInp[i].out[j][idx];
                ICPrefAddInp[i].b[j][idx] <== i == 0 ? IC[0][j][idx] : ICPrefAddInp[i - 1].out[j][idx];
            }
        }
        ICPrefAddInp[i].aIsInfinity <== ICmultInp[i].isInfinity;
        ICPrefAddInp[i].bIsInfinity <== i == 0 ? 0 : ICPrefAddInp[i - 1].isInfinity;
    }

    component AxB = BLSAtePairing(n, k, p);
    component VKxGamma2 = BLSAtePairing(n, k, p);
    component CxDelta2 = BLSAtePairing(n, k, p);
    for (var i = 0;i < 2;i++) {
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k;idx++) {
                AxB.P[i][j][idx] <== pb[i][j][idx];
                VKxGamma2.P[i][j][idx] <== gamma2[i][j][idx];
                CxDelta2.P[i][j][idx] <== delta2[i][j][idx];
            }
        }
        for (var idx = 0;idx < k;idx++) {
            AxB.Q[i][idx] <== pa[i][idx];
            VKxGamma2.Q[i][idx] <== ICPrefAddInp[publicInputCount - 1].out[i][idx];
            CxDelta2.Q[i][idx] <== pc[i][idx];
        }
    }

    component RHS_partial = Fp12Multiply(n, k, p);
    for (var i = 0;i < 6;i++) {
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k;idx++) {
                RHS_partial.a <== alfa1xbeta2[i][j][idx];
                RHS_partial.b <== VKxGamma2.out[i][j][idx];
            }
        }
    }

    component RHS_full = Fp12Multiply(n, k, p);
    for (var i = 0;i < 6;i++) {
        for (var j = 0;j < 2;j++) {
            for (var idx = 0;idx < k;idx++) {
                RHS_full.a <== RHS_partial.out[i][j][idx];
                RHS_full.b <== CxDelta2.out[i][j][idx];
            }
        }
    }

    component areBigEqual[6][2], areFP12PrefixEqual[6];
    for (var i = 0;i < 6;i++) {
        for (var j = 0;j < 2;j++) {
            areBigEqual[i][j] = BigIsEqual(k);
            for (var idx = 0;idx < k;idx++) {
                areBigEqual[i][j].a[idx] <== AxB.out[i][j][idx];
                areBigEqual[i][j].b[idx] <== RHS_full.out[i][j][idx];
            }
        }
    }

    for (var i = 0;i < 6;i++) {
        areFP12PrefixEqual[i] = AND();
        areFP12PrefixEqual[i].a <== i == 0 ? 1 : areFP12PrefixEqual[i-1].out;
        areFP12PrefixEqual[i].b <== areBigEqual[i][0].out*areBigEqual[i][1].out;
    }
    out <== areFP12PrefixEqual[5];
}


template Example (n, k) {
    signal input in[2][k];
    signal input inIsInfinity;
    signal input x[k];
    var p[50] = get_BLS12_381_prime(n, k);
    var b = 4;

    // component doubler = EllipticCurveDouble(n, k, 0, b, p);
    // for (var j = 0;j < 2;j++) {
    //     for (var idx = 0;idx < k;idx++) {
    //         doubler.in[j][idx] <== in[j][idx];
    //     }
    // }
    // for (var j = 0;j < 2;j++) {
    //     for (var idx = 0;idx < k;idx++) {
    //         log(j);
    //         log(idx);
    //         log(doubler.out[j][idx]);
    //     }
    // }

    component mine = MyEllipticCurveScalarMultiply(n, k, b, p);
    for (var j = 0;j < 2;j++) {
        for (var idx = 0;idx < k;idx++) {
            mine.in[j][idx] <== in[j][idx];
        }
    }
    for (var idx = 0;idx < k;idx++) {
        mine.x[idx] <== x[idx];
    }
    mine.inIsInfinity <== inIsInfinity;
    for (var j = 0;j < 2;j++) {
        for (var idx = 0;idx < k;idx++) {
            log(j);
            log(idx);
            log(mine.out[j][idx]);
        }
    }
}

component main { public [ in, inIsInfinity ] } = Example(55, 7);
