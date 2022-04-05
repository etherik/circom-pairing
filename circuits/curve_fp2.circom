pragma circom 2.0.3;

include "../node_modules/circomlib/circuits/bitify.circom";

include "./bigint.circom";
include "./bigint_func.circom";
include "./fp.circom";
include "./fp2.circom";
include "./fp12.circom";
include "./bls12_381_func.circom";

// in[i] = (x_i, y_i) 
// Implements constraint: (y_1 + y_3) * (x_2 - x_1) - (y_2 - y_1)*(x_1 - x_3) = 0 mod p
// used to show (x1, y1), (x2, y2), (x3, -y3) are co-linear
template PointOnLineFp2(n, k, p) {
    signal input in[3][2][2][k]; 

    var LOGK = log_ceil(k);
    var LOGK2 = log_ceil(16*k*k);
    assert(3*n + LOGK2 < 251);

    // AKA check point on line 
    component left = BigMultShortLong2D(n, k, 2); // 3 x 2k-1 registers in [0, 8k*2^{2n+1})
    for(var i = 0; i < 2; i ++) {
        for (var j = 0; j < k; j ++) {
            left.a[i][j] <== in[0][1][i][j] + in[2][1][i][j];
            left.b[i][j] <== in[1][0][i][j] - in[0][0][i][j];
        }
    }

    component right = BigMultShortLong2D(n, k, 2); // 3 x 2k-1 registers in [0, 8k*2^{2n+1})
    for(var i = 0; i < 2; i ++) {
        for (var j = 0; j < k; j ++) {
            right.a[i][j] <== in[1][1][i][j] - in[0][1][i][j];
            right.b[i][j] <== in[0][0][i][j] - in[2][0][i][j];
        }
    }
    
    component diff_red[2]; 
    diff_red[0] = PrimeReduce(n, k, k-1, p, 3*n + 2*LOGK + 4);
    diff_red[1] = PrimeReduce(n, k, k-1, p, 3*n + 2*LOGK + 4);
    for(var i=0; i<2*k-1; i++) {
        diff_red[0].in[i] <== left.out[0][i] - left.out[2][i] - right.out[0][i] + right.out[2][i];
        diff_red[1].in[i] <== left.out[1][i] - right.out[1][i]; 
    }
    // diff_red has k registers in [0, 16*k^2*2^{3n} )
    component diff_mod[2];
    for (var j = 0; j < 2; j ++) {
        diff_mod[j] = SignedCheckCarryModToZero(n, k, 3*n + LOGK2, p);
        for (var i = 0; i < k; i ++) {
            diff_mod[j].in[i] <== diff_red[j].out[i];
        }
    }
}

// in = (x, y)
// Implements:
// x^3 + ax + b - y^2 = 0 mod p
// Assume: a, b in [0, 2^n) 

// test: component main { public [in] } = PointOnCurveFp2(2, 2, 0, 3, [1,1]);
// 
// /* INPUT = {
//     "in": [[[2,0],[3,0]],[[1,0],[2,0]]]
// } */
template PointOnCurveFp2(n, k, a, b, p){
    signal input in[2][2][k]; 

    var LOGK = log_ceil(k);
    var LOGK2 = log_ceil( (2*k-1)*k*k*2 );
    assert(4*n + 3 * LOGK + 4 < 251);

    // compute x^3, y^2 
    component x_sq = SignedFp2MultiplyNoCarryUnequal(n, k, k, 2*n+1+LOGK); // 2k-1 registers in [0, 2*k*2^{2n}) 
    component y_sq = SignedFp2MultiplyNoCarryUnequal(n, k, k, 2*n+1+LOGK); // 2k-1 registers in [0, 2*k*2^{2n}) 
    for (var i = 0; i < 2; i ++) {
        for (var j = 0; j < k ; j ++) {
            x_sq.a[i][j] <== in[0][i][j];
            x_sq.b[i][j] <== in[0][i][j];
            y_sq.a[i][j] <== in[1][i][j];
            y_sq.b[i][j] <== in[1][i][j];
        }
    }
    component x_cu = SignedFp2MultiplyNoCarryUnequal(n, 2*k-1, k, 3*n+2*LOGK+2); // 3k-2 registers in [0, 4*k^2 * 2^{3n}) 
    for (var i = 0; i < 2; i ++) {
        for (var j = 0; j < 2*k-1; j ++) {
            x_cu.a[i][j] <== x_sq.out[i][j];
        }
        for (var j = 0; j < k; j ++) {
            x_cu.b[i][j] <== in[0][i][j];
        }
    }

    // x_cu + a x + b has 3k-2 registers < 2^{3n + 2LOGK + 2} 
    component cu_red[2];
    for (var j = 0; j < 2; j ++) {
        cu_red[j] = PrimeReduce(n, k, 2*k-2, p, 4*n + 3*LOGK + 4);
        for(var i=0; i<3*k-2; i++){
            if(i == 0) {
                if (j == 0)
                    cu_red[j].in[i] <== x_cu.out[j][i] + a * in[0][j][i] + b;
                else
                    cu_red[j].in[i] <== x_cu.out[j][i] + a * in[0][j][i];
            }
            else{
                if(i < k)
                    cu_red[j].in[i] <== x_cu.out[j][i] + a * in[0][j][i]; 
                else
                    cu_red[j].in[i] <== x_cu.out[j][i];
            }
        }
    }
    // cu_red has k registers < (2k-1)*2^{4n + 2LOGK + 1} < 2^{4n + 3LOGK + 4}

    component y_sq_red[2];
    for (var i = 0; i < 2; i ++) {
        y_sq_red[i] = PrimeReduce(n, k, k-1, p, 4*n + 3*LOGK + 4);
        for(var j=0; j<2*k-1; j++){
            y_sq_red[i].in[j] <== y_sq.out[i][j];
        }
    }

    component constraint[2];
    constraint[0] = SignedCheckCarryModToZero(n, k, 4*n + 3*LOGK2+4, p);
    constraint[1] = SignedCheckCarryModToZero(n, k, 4*n + 3*LOGK2+4, p);
    for(var i=0; i<k; i++){
        constraint[0].in[i] <== cu_red[0].out[i] - y_sq_red[0].out[i]; 
        constraint[1].in[i] <== cu_red[1].out[i] - y_sq_red[1].out[i];
    }
}

// component main { public [in] } = PointOnTangentFp2(2, 2, 2, [1, 1]);

// /* INPUT = {
//     "in": [[[[1,0],[1,0]],[[0,0],[2,0]]], [[[1,0],[2,0]],[[2,0],[0,1]]]]
// } */

// in[0] = (x_1, y_1), in[1] = (x_3, y_3) 
// Checks that the line between (x_1, y_1) and (x_3, -y_3) is equal to the tangent line to the elliptic curve at the point (x_1, y_1)
// Implements: 
// (y_1 + y_3) = lambda * (x_1 - x_3)
// where lambda = (3 x_1^2 + a)/(2 y_1) 
// Actual constraint is 2y_1 (y_1 + y_3) = (3 x_1^2 + a ) ( x_1 - x_3 )
template PointOnTangentFp2(n, k, a, p){
    signal input in[2][2][2][k];
    
    var LOGK = log_ceil(k);
    var LOGK3 = log_ceil((2*k-1)*7*k*k);
    assert(4*n + LOGK3 < 251);
    component x_sq = SignedFp2MultiplyNoCarryUnequal(n, k, k, 2*n+1+LOGK); // 2k-1 registers in [0, 2*k*2^{2n}) 
    for (var i = 0; i < 2; i ++) {
        for (var j = 0; j < k ; j ++) {
            x_sq.a[i][j] <== in[0][0][i][j];
            x_sq.b[i][j] <== in[0][0][i][j];
        }
    }
    component right = SignedFp2MultiplyNoCarryUnequal(n, 2*k-1, k, 3*n + 2*LOGK + 3); // 3k-2 registers < 2*3*k^2*2^{3n} 
    for(var i=0; i<2*k-1; i++){
        if(i == 0) {
            right.a[0][i] <== 3 * x_sq.out[0][i] + a; // registers in [0, 3*k*2^{2n} + 2^n )  
            right.a[1][i] <== 3 * x_sq.out[1][i];
        }
        else {
            right.a[0][i] <== 3 * x_sq.out[0][i];
            right.a[1][i] <== 3 * x_sq.out[1][i];
        }
    }
    for(var i=0; i<k; i++){
        right.b[0][i] <== in[0][0][0][i] - in[1][0][0][i]; 
        right.b[1][i] <== in[0][0][1][i] - in[1][0][1][i];
    }
    
    component left = SignedFp2MultiplyNoCarryUnequal(n, k, k, 2*n + 3 + LOGK); // 2k-1 registers in [0, k * 2^{2n+3})
    for(var i=0; i<k; i++){
        left.a[0][i] <== 2*in[0][1][0][i];
        left.a[1][i] <== 2*in[0][1][1][i];
        left.b[0][i] <== in[0][1][0][i] + in[1][1][0][i];
        left.b[1][i] <== in[0][1][1][i] + in[1][1][1][i];
    }
    
    // prime reduce right - left 
    component diff_red[2];
    for (var i = 0; i < 2; i ++) {
        diff_red[i] = PrimeReduce(n, k, 2*k-2, p, 4*n + LOGK3);
        for (var j = 0; j < 3*k-2; j ++) {
            if (j < 2*k-1) {
                diff_red[i].in[j] <== right.out[i][j] - left.out[i][j];
            }
            else {
                diff_red[i].in[j] <== right.out[i][j];
            }
        }
    }
    // inputs of diff_red has registers < 7*k^2*2^{3n} 
    // diff_red.out has registers < (2k-1)*7*k^2 * 2^{4n}
    component constraint[2];
    for (var i = 0; i < 2; i ++) {
        constraint[i] = SignedCheckCarryModToZero(n, k, 4*n + LOGK3, p);
        for (var j = 0; j < k; j ++) {
            constraint[i].in[j] <== diff_red[i].out[j];
        }
    }
}

// requires x_1 != x_2
// assume p is size k array, the prime that curve lives over 
//
// Implements:
//  Given a = (x_1, y_1) and b = (x_2, y_2), 
//      assume x_1 != x_2 and a != -b, 
//  Find a + b = (x_3, y_3)
// By solving:
//  x_1 + x_2 + x_3 - lambda^2 = 0 mod p
//  y_3 = lambda (x_1 - x_3) - y_1 mod p
//  where lambda = (y_2-y_1)/(x_2-x_1) is the slope of the line between (x_1, y_1) and (x_2, y_2)
// these equations are equivalent to:
//  (x_1 + x_2 + x_3)*(x_2 - x_1)^2 = (y_2 - y_1)^2 mod p
//  (y_1 + y_3)*(x_2 - x_1) = (y_2 - y_1)*(x_1 - x_3) mod p
template EllipticCurveAddUnequalFp2(n, k, p) { // changing q's to p's for my sanity
    signal input a[2][2][k];
    signal input b[2][2][k];

    signal output out[2][2][k];

    var LOGK = log_ceil(k);
    var LOGK3 = log_ceil( (12*k+1)*k*(2*k-1)); 
    assert(4*n + LOGK3 + 2< 251);

    // precompute lambda and x_3 and then y_3
    var dy[2][50] = find_Fp2_diff(n, k, b[1], a[1], p);
    var dx[2][50] = find_Fp2_diff(n, k, b[0], a[0], p); 
    var dx_inv[2][50] = find_Fp2_inverse(n, k, dx, p);
    var lambda[2][50] = find_Fp2_product(n, k, dy, dx_inv, p);
    var lambda_sq[2][50] = find_Fp2_product(n, k, lambda, lambda, p);
    // out[0] = x_3 = lamb^2 - a[0] - b[0] % p
    // out[1] = y_3 = lamb * (a[0] - x_3) - a[1] % p
    var x3[2][50] = find_Fp2_diff(n, k, find_Fp2_diff(n, k, lambda_sq, a[0], p), b[0], p);
    var y3[2][50] = find_Fp2_diff(n, k, find_Fp2_product(n, k, lambda, find_Fp2_diff(n, k, a[0], x3, p), p), a[1], p);

    for(var i = 0; i < k; i++){
        out[0][0][i] <-- x3[0][i];
        out[0][1][i] <-- x3[1][i];
        out[1][0][i] <-- y3[0][i];
        out[1][1][i] <-- y3[1][i];
    }
    
    // constrain x_3 by CUBIC (x_1 + x_2 + x_3) * (x_2 - x_1)^2 - (y_2 - y_1)^2 = 0 mod p
    
    component dx_sq = BigMultShortLong2D(n, k, 2); // 2k-1 registers < 4k*2^{2n} 
    component dy_sq = BigMultShortLong2D(n, k, 2); // 2k-1 registers < 4k*2^{2n}
    for (var i = 0; i < 2; i ++) {
        for (var j = 0; j < k; j ++) {
            dx_sq.a[i][j] <== b[0][i][j] - a[0][i][j];
            dx_sq.b[i][j] <== b[0][i][j] - a[0][i][j];
            dy_sq.a[i][j] <== b[1][i][j] - a[1][i][j];
            dy_sq.b[i][j] <== b[1][i][j] - a[1][i][j];
        }
    }

    // x_1 + x_2 + x_3 has registers in [0, 3*2^n) 
    component cubic = BigMultShortLong2DUnequal(n, k, 2*k-1, 2, 2); // 3k-2 x 3 registers < 24 * k^2 * 2^{3n} ) 
    for(var i=0; i<k; i++) {
        cubic.a[0][i] <== a[0][0][i] + b[0][0][i] + out[0][0][i]; 
        cubic.a[1][i] <== a[0][1][i] + b[0][1][i] + out[0][1][i];
    }
    for(var i=0; i<2*k-1; i++){
        cubic.b[0][i] <== dx_sq.out[0][i] - dx_sq.out[2][i];
        cubic.b[1][i] <== dx_sq.out[1][i];
    }

    component cubic_red[2];
    cubic_red[0] = PrimeReduce(n, k, 2*k-2, p, 4*n + LOGK3 + 2);
    cubic_red[1] = PrimeReduce(n, k, 2*k-2, p, 4*n + LOGK3 + 2);
    for(var i=0; i<2*k-1; i++) {
        // get i^2 parts too!
        cubic_red[0].in[i] <== cubic.out[0][i] - cubic.out[2][i] - dy_sq.out[0][i] + dy_sq.out[2][i]; // registers in < 12*k^2*2^{3n} + 4k*2^{2n} < (12k+1)k * 2^{3n} )
        cubic_red[1].in[i] <== cubic.out[1][i] - dy_sq.out[1][i]; // registers in < 12*k^2*2^{3n} + 4k*2^{2n} < (12k+1)k * 2^{3n} )
    }
    for(var i=2*k-1; i<3*k-2; i++) {
        cubic_red[0].in[i] <== cubic.out[0][i] - cubic.out[2][i]; 
        cubic_red[1].in[i] <== cubic.out[1][i];
    }
    // cubic_red has k registers < (2k-1) (12k+1)k * 2^{4n}
    
    component cubic_mod[2];
    cubic_mod[0] = SignedCheckCarryModToZero(n, k, 4*n + LOGK3 + 2, p);
    cubic_mod[1] = SignedCheckCarryModToZero(n, k, 4*n + LOGK3 + 2, p);
    for(var i=0; i<k; i++) {
        cubic_mod[0].in[i] <== cubic_red[0].out[i];
        cubic_mod[1].in[i] <== cubic_red[1].out[i];
    }
    // END OF CONSTRAINING x3
    
    // constrain y_3 by (y_1 + y_3) * (x_2 - x_1) = (y_2 - y_1)*(x_1 - x_3) mod p
    component y_constraint = PointOnLineFp2(n, k, p); // 2k-1 registers in [0, k*2^{2n+1})
    for(var i = 0; i < k; i++)for(var j=0; j<2; j++){
        for(var ind = 0; ind < 2; ind ++) {
            y_constraint.in[0][j][ind][i] <== a[j][ind][i];
            y_constraint.in[1][j][ind][i] <== b[j][ind][i];
            y_constraint.in[2][j][ind][i] <== out[j][ind][i];
        }
    }
    // END OF CONSTRAINING y3

    // check if out[][] has registers in [0, 2^n) and each out[i] is in [0, p)
    // re-using Fp2 code by considering (x_3, y_3) as a 2d-vector over Fp
    component range_check[2];
    range_check[0] = CheckValidFp2(n, k, p);
    range_check[1] = CheckValidFp2(n, k, p);
    for(var j=0; j<2; j++)for(var i=0; i<k; i++) {
        range_check[0].in[j][i] <== out[0][j][i];
        range_check[1].in[j][i] <== out[1][j][i];
    }
}

// component main { public [a,b] } = EllipticCurveAddUnequalFp2(2, 2, [1,1]);

// /* INPUT = {
//     "a": [[[1,0],[1,0]],[[2,0],[3,0]]],
//     "b": [[[2,0],[1,0]],[[1,0],[2,0]]]
// } */
// requires x_1 != x_2
// assume p is size k array, the prime that curve lives over 
//
// Implements:
//  Given a = (x_1, y_1) and b = (x_2, y_2), 
//      assume x_1 != x_2 and a != -b, 
//  Find a + b = (x_3, y_3)
// By solving:
//  x_1 + x_2 + x_3 - lambda^2 = 0 mod p
//  y_3 = lambda (x_1 - x_3) - y_1 mod p
//  where lambda = (y_2-y_1)/(x_2-x_1) is the slope of the line between (x_1, y_1) and (x_2, y_2)
// these equations are equivalent to:
//  (x_1 + x_2 + x_3)*(x_2 - x_1)^2 = (y_2 - y_1)^2 mod p
//  (y_1 + y_3)*(x_2 - x_1) = (y_2 - y_1)*(x_1 - x_3) mod p
template EllipticCurveAddUnequalFp2(n, k, p) { // changing q's to p's for my sanity
    signal input a[2][2][k];
    signal input b[2][2][k];

    signal output out[2][2][k];

    var LOGK = log_ceil(k);
    var LOGK3 = log_ceil( (12*k+1)*k*(2*k-1)); 
    assert(4*n + LOGK3 + 2< 251);

    // precompute lambda and x_3 and then y_3
    var dy[2][50] = find_Fp2_diff(n, k, b[1], a[1], p);
    var dx[2][50] = find_Fp2_diff(n, k, b[0], a[0], p); 
    var dx_inv[2][50] = find_Fp2_inverse(n, k, dx, p);
    var lambda[2][50] = find_Fp2_product(n, k, dy, dx_inv, p);
    var lambda_sq[2][50] = find_Fp2_product(n, k, lambda, lambda, p);
    // out[0] = x_3 = lamb^2 - a[0] - b[0] % p
    // out[1] = y_3 = lamb * (a[0] - x_3) - a[1] % p
    var x3[2][50] = find_Fp2_diff(n, k, find_Fp2_diff(n, k, lambda_sq, a[0], p), b[0], p);
    var y3[2][50] = find_Fp2_diff(n, k, find_Fp2_product(n, k, lambda, find_Fp2_diff(n, k, a[0], x3, p), p), a[1], p);

    for(var i = 0; i < k; i++){
        out[0][0][i] <-- x3[0][i];
        out[0][1][i] <-- x3[1][i];
        out[1][0][i] <-- y3[0][i];
        out[1][1][i] <-- y3[1][i];
    }
    
    // constrain x_3 by CUBIC (x_1 + x_2 + x_3) * (x_2 - x_1)^2 - (y_2 - y_1)^2 = 0 mod p
    
    component dx_sq = BigMultShortLong2D(n, k, 2); // 2k-1 registers < 4k*2^{2n} 
    component dy_sq = BigMultShortLong2D(n, k, 2); // 2k-1 registers < 4k*2^{2n}
    for (var i = 0; i < 2; i ++) {
        for (var j = 0; j < k; j ++) {
            dx_sq.a[i][j] <== b[0][i][j] - a[0][i][j];
            dx_sq.b[i][j] <== b[0][i][j] - a[0][i][j];
            dy_sq.a[i][j] <== b[1][i][j] - a[1][i][j];
            dy_sq.b[i][j] <== b[1][i][j] - a[1][i][j];
        }
    }

    // x_1 + x_2 + x_3 has registers in [0, 3*2^n) 
    component cubic = BigMultShortLong2DUnequal(n, k, 2*k-1, 2, 2); // 3k-2 x 3 registers < 24 * k^2 * 2^{3n} ) 
    for(var i=0; i<k; i++) {
        cubic.a[0][i] <== a[0][0][i] + b[0][0][i] + out[0][0][i]; 
        cubic.a[1][i] <== a[0][1][i] + b[0][1][i] + out[0][1][i];
    }
    for(var i=0; i<2*k-1; i++){
        cubic.b[0][i] <== dx_sq.out[0][i] - dx_sq.out[2][i];
        cubic.b[1][i] <== dx_sq.out[1][i];
    }

    component cubic_red[2];
    cubic_red[0] = PrimeReduce(n, k, 2*k-2, p, 4*n + LOGK3 + 2);
    cubic_red[1] = PrimeReduce(n, k, 2*k-2, p, 4*n + LOGK3 + 2);
    for(var i=0; i<2*k-1; i++) {
        // get i^2 parts too!
        cubic_red[0].in[i] <== cubic.out[0][i] - cubic.out[2][i] - dy_sq.out[0][i] + dy_sq.out[2][i]; // registers in < 12*k^2*2^{3n} + 4k*2^{2n} < (12k+1)k * 2^{3n} )
        cubic_red[1].in[i] <== cubic.out[1][i] - dy_sq.out[1][i]; // registers in < 12*k^2*2^{3n} + 4k*2^{2n} < (12k+1)k * 2^{3n} )
    }
    for(var i=2*k-1; i<3*k-2; i++) {
        cubic_red[0].in[i] <== cubic.out[0][i] - cubic.out[2][i]; 
        cubic_red[1].in[i] <== cubic.out[1][i];
    }
    // cubic_red has k registers < (2k-1) (12k+1)k * 2^{4n}
    
    component cubic_mod[2];
    cubic_mod[0] = SignedCheckCarryModToZero(n, k, 4*n + LOGK3 + 2, p);
    cubic_mod[1] = SignedCheckCarryModToZero(n, k, 4*n + LOGK3 + 2, p);
    for(var i=0; i<k; i++) {
        cubic_mod[0].in[i] <== cubic_red[0].out[i];
        cubic_mod[1].in[i] <== cubic_red[1].out[i];
    }
    // END OF CONSTRAINING x3
    
    // constrain y_3 by (y_1 + y_3) * (x_2 - x_1) = (y_2 - y_1)*(x_1 - x_3) mod p
    component y_constraint = PointOnLineFp2(n, k, p); // 2k-1 registers in [0, k*2^{2n+1})
    for(var i = 0; i < k; i++)for(var j=0; j<2; j++){
        for(var ind = 0; ind < 2; ind ++) {
            y_constraint.in[0][j][ind][i] <== a[j][ind][i];
            y_constraint.in[1][j][ind][i] <== b[j][ind][i];
            y_constraint.in[2][j][ind][i] <== out[j][ind][i];
        }
    }
    // END OF CONSTRAINING y3

    // check if out[][] has registers in [0, 2^n) and each out[i] is in [0, p)
    // re-using Fp2 code by considering (x_3, y_3) as a 2d-vector over Fp
    component range_check[2];
    range_check[0] = CheckValidFp2(n, k, p);
    range_check[1] = CheckValidFp2(n, k, p);
    for(var j=0; j<2; j++)for(var i=0; i<k; i++) {
        range_check[0].in[j][i] <== out[0][j][i];
        range_check[1].in[j][i] <== out[1][j][i];
    }
}

// component main { public [in] } = EllipticCurveDoubleFp2(2, 2, 0, 2, [3,1]);

// /* INPUT = {
//     "in": [[[2,0],[1,0]],[[1,0],[2,0]]]
// } */

// Elliptic curve is E : y**2 = x**3 + ax + b
// assuming a < 2^n for now
// Note that for BLS12-381, a = 0, b = 4

// Implements:
// computing 2P on elliptic curve E for P = (x_1, y_1)
// formula from https://crypto.stanford.edu/pbc/notes/elliptic/explicit.html
// x_1 = in[0], y_1 = in[1]
// assume y_1 != 0 (otherwise 2P = O)

// lamb =  (3x_1^2 + a) / (2 y_1) % p
// x_3 = out[0] = lambda^2 - 2 x_1 % p
// y_3 = out[1] = lambda (x_1 - x_3) - y_1 % p

// We precompute (x_3, y_3) and then constrain by showing that:
// * (x_3, y_3) is a valid point on the curve 
// * the slope (y_3 - y_1)/(x_3 - x_1) equals 
// * x_1 != x_3 
template EllipticCurveDoubleFp2(n, k, a, b, p) {
    signal input in[2][2][k];
    signal output out[2][2][k];

    var long_a[2][k];
    var long_3[2][k];
    long_a[0][0] = a;
    long_3[0][0] = 3;
    long_a[1][0] = 0;
    long_3[1][0] = 0;
    for (var i = 1; i < k; i++) {
        long_a[0][i] = 0;
        long_3[0][i] = 0;
        long_a[1][i] = 0;
        long_3[1][i] = 0;
    }

    // precompute lambda 
    var lamb_num[2][50] = find_Fp2_sum(n, k, long_a, find_Fp2_product(n, k, long_3, find_Fp2_product(n, k, in[0], in[0], p), p), p);
    var lamb_denom[2][50] = find_Fp2_sum(n, k, in[1], in[1], p);
    var lamb[2][50] = find_Fp2_product(n, k, lamb_num, find_Fp2_inverse(n, k, lamb_denom, p), p);

    // precompute x_3, y_3
    var x3[2][50] = find_Fp2_diff(n, k, find_Fp2_product(n, k, lamb, lamb, p), find_Fp2_sum(n, k, in[0], in[0], p), p);
    var y3[2][50] = find_Fp2_diff(n, k, find_Fp2_product(n, k, lamb, find_Fp2_diff(n, k, in[0], x3, p), p), in[1], p);
    
    for(var i=0; i<k; i++){
        out[0][0][i] <-- x3[0][i];
        out[0][1][i] <-- x3[1][i];
        out[1][0][i] <-- y3[0][i];
        out[1][1][i] <-- y3[1][i];
    }
    // check if out[][] has registers in [0, 2^n) and each out[i] is in [0, p)
    // re-using Fp2 code by considering (x_3, y_3) as a 2d-vector over Fp
    component range_check[2];
    range_check[0] = CheckValidFp2(n, k, p);
    range_check[1] = CheckValidFp2(n, k, p);
    for(var j=0; j<2; j++)for(var i=0; i<k; i++) {
        range_check[0].in[j][i] <== out[0][j][i];
        range_check[1].in[j][i] <== out[1][j][i];
    }

    component point_on_tangent = PointOnTangentFp2(n, k, a, p);
    for(var j=0; j<2; j++)for(var i=0; i<k; i++){
        point_on_tangent.in[0][j][0][i] <== in[j][0][i];
        point_on_tangent.in[0][j][1][i] <== in[j][1][i];
        point_on_tangent.in[1][j][0][i] <== out[j][0][i];
        point_on_tangent.in[1][j][1][i] <== out[j][1][i];
    }
    
    component point_on_curve = PointOnCurveFp2(n, k, a, b, p);
    for(var j=0; j<2; j++)for(var i=0; i<k; i++) {
        point_on_curve.in[j][0][i] <== out[j][0][i];
        point_on_curve.in[j][1][i] <== out[j][1][i];
    }
    
    component x3_eq_x1 = IsArrayEqual(2*k);
    for(var i = 0; i < k; i++){
        x3_eq_x1.in[0][i] <== out[0][0][i];
        x3_eq_x1.in[1][i] <== in[0][0][i];
        x3_eq_x1.in[0][i+k] <== out[0][1][i];
        x3_eq_x1.in[1][i+k] <== in[0][1][i];
    }
    x3_eq_x1.out === 0;
}

// component main { public [P, Q] } = SignedLineFunctionUnequalNoCarryFp2(2, 2, 8);

// /* INPUT = {
//     "P": [ [[[1,0],[1,0]],[[1,0],[0,0]]], 
//                 [[[1,0],[1,0]],[[0,0],[1,0]]] ], 
//     "Q": [ [[[1,0],[0,0]],[[1,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]]],
//             [[[1,0],[0,0]],[[0,0],[1,0]],[[0,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]]] ]
// } */

// Inputs:
//  P is 2 x 2 x 2 x k array where P0 = (x_1, y_1) and P1 = (x_2, y_2) are points in E(Fp2)
//  Q is 2 x 6 x 2 x k array representing point (X, Y) in E(Fp12)
// Assuming (x_1, y_1) != (x_2, y_2)
// Output:
//  out is 6 x 2 x (2k-1) array representing element of Fp12 equal to:
//  (y_1 - y_2) X + (x_2 - x_1) Y + (x_1 y_2 - x_2 y_1)
// We evaluate out without carries
// If all registers of P, Q are in [0, 2^n),
// Then all registers of out have abs val < 6k * 2^{2n} )
// m_out is the expected max number of bits in the output registers
template SignedLineFunctionUnequalNoCarryFp2(n, k, m_out){
    signal input P[2][2][2][k];
    signal input Q[2][6][2][k];
    signal output out[6][2][2*k-1];

    // (y_1 - y_2) X
    var LOGK = log_ceil(k);
    component Xmult = SignedFp12Fp2MultiplyNoCarry(n, k, 2*n + LOGK+1); // registers in [0, 4k*2^{2n} )
    // (x_2 - x_1) Y
    component Ymult = SignedFp12Fp2MultiplyNoCarry(n, k, 2*n + LOGK+1);
    for(var i = 0; i < 2; i ++) {
        for(var j=0; j<k; j++){
            Xmult.a[i][j] <== P[0][1][i][j] - P[1][1][i][j];
            
            Ymult.a[i][j] <== P[1][0][i][j] - P[0][0][i][j];
        }
    }
    for(var i=0; i<6; i++)for(var j=0; j<2; j++)for(var idx=0; idx<k; idx++){
        Xmult.b[i][j][idx] <== Q[0][i][j][idx];

        Ymult.b[i][j][idx] <== Q[1][i][j][idx]; 
    } 
    
    component x1y2 = BigMultShortLong2D(n, k, 2); // registers in [0, 2k*2^{2n}) 
    component x2y1 = BigMultShortLong2D(n, k, 2);
    for(var i = 0; i < 2; i ++) {
        for(var j=0; j<k; j++){
            x1y2.a[i][j] <== P[0][0][i][j]; 
            x1y2.b[i][j] <== P[1][1][i][j];
            
            x2y1.a[i][j] <== P[1][0][i][j]; 
            x2y1.b[i][j] <== P[0][1][i][j];
        }
    }
    
    for(var i=0; i<6; i++)for(var j=0; j<2; j++)for(var idx=0; idx<2*k-1; idx++){
        if( i==0){
            if (j == 1) {
                out[i][j][idx] <== Xmult.out[i][j][idx] + Ymult.out[i][j][idx] + x1y2.out[j][idx] - x2y1.out[j][idx]; // register < 6k*2^{2n} 
            }
            else {
                out[i][j][idx] <== Xmult.out[i][j][idx] + Ymult.out[i][j][idx] + x1y2.out[0][idx] - x1y2.out[2][idx] - x2y1.out[0][idx] + x2y1.out[2][idx];
            }
        }else 
            out[i][j][idx] <== Xmult.out[i][j][idx] + Ymult.out[i][j][idx]; // register in [0, 4k*2^{2n+1} )
    }
    /*component range_checks[6][4][2*k-1];
    for (var outer = 0; outer < 6; outer ++) {
        for (var i = 0; i < 2; i ++) {
            for (var j = 0; j < 2*k-1; j ++) {
                range_checks[outer][i][j] = Num2Bits(m_out);
                range_checks[outer][i][j].in <== out[outer][i][j];
            }
        }
    }*/
}

// component main { public [P, Q] } = SignedLineFunctionEqualNoCarryFp2(2, 2, 8);

// /* INPUT = {
//     "P": [[[1,0],[1,0]],[[1,0],[2,0]]], 
//     "Q": [ [[[1,0],[0,0]],[[1,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]]],
//             [[[1,0],[0,0]],[[0,0],[1,0]],[[0,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]]] ]
// } */

// Assuming curve is of form Y^2 = X^3 + b for now (a = 0) for better register bounds 
// Inputs:
//  P is 2 x 2 x k array where P = (x, y) is a point in E(Fp2) 
//  Q is 2 x 6 x 2 x k array representing point (X, Y) in E(Fp12) 
// Output: 
//  out is 6 x 2 x (3k-2) array representing element of Fp12 equal to:
//  3 x^2 (-X + x) + 2 y (Y - y)
// We evaluate out without carries, with signs
// If P, Q have registers in [0, 2^n) 
// Then out has registers in [0, 6k^2*2^{3n} + 4k*2^{2n} < (6k + 4/2^n )*k*2^{3n})
// m_out is the expected max number of bits in the output registers
template SignedLineFunctionEqualNoCarryFp2(n, k, m_out){
    signal input P[2][2][k]; 
    signal input Q[2][6][2][k];
    signal output out[6][2][3*k-2];
    var LOGK = log_ceil(k);

    component x_sq3 = BigMultShortLong2D(n, k, 2); // 2k-1 registers in [0, 6*k*2^{2n} )
    for(var i=0; i<2; i++){
        for(var j = 0; j < k; j ++) {
            x_sq3.a[i][j] <== 3*P[0][i][j];
            x_sq3.b[i][j] <== P[0][i][j];
        }
    } 
    
    // 3 x^2 (-X + x)
    component Xmult = SignedFp12Fp2MultiplyNoCarryUnequal(n, 2*k-1, k, 3*n + 2*LOGK + 3); // 3k-2 registers < 12 * k^2 * 2^{3n})
    for(var idx=0; idx<2*k-1; idx++){
        Xmult.a[0][idx] <== x_sq3.out[0][idx] - x_sq3.out[2][idx];
        Xmult.a[1][idx] <== x_sq3.out[1][idx];
    }
    for(var i=0; i<6; i++)for(var j=0; j<2; j++)for(var idx=0; idx<k; idx++){
        if(i==0)
            Xmult.b[i][j][idx] <== P[0][j][idx] - Q[0][i][j][idx];
        else
            Xmult.b[i][j][idx] <== -Q[0][i][j][idx];
    }

    // 2 y (Y-y)
    component Ymult = SignedFp12Fp2MultiplyNoCarry(n, k, 2*n + LOGK + 2); // 2k-1 registers < 8k*2^{2n} 
    for(var idx=0; idx < k; idx++){
        Ymult.a[0][idx] <== 2*P[1][0][idx];
        Ymult.a[1][idx] <== 2*P[1][1][idx];
    }
    for(var i=0; i<6; i++)for(var j=0; j<2; j++)for(var idx=0; idx<k; idx++){
        if(i==0)
            Ymult.b[i][j][idx] <== Q[1][i][j][idx] - P[1][j][idx];
        else
            Ymult.b[i][j][idx] <== Q[1][i][j][idx];
    }
    
    for(var i=0; i<6; i++)for(var j=0; j<2; j++)for(var idx=0; idx<3*k-2; idx++){
        if(idx < 2*k-1)
            out[i][j][idx] <== Xmult.out[i][j][idx] + Ymult.out[i][j][idx];
        else
            out[i][j][idx] <== Xmult.out[i][j][idx];
    }
    /*component range_checks[6][4][3*k-2];
    for (var outer = 0; outer < 6; outer ++) {
        for (var i = 0; i < 2; i ++) {
            for (var j = 0; j < 3*k-2; j ++) {
                range_checks[outer][i][j] = Num2Bits(m_out);
                range_checks[outer][i][j].in <== out[outer][i][j];
            }
        }
    }*/
}

// component main { public [P, Q] } = LineFunctionUnequalFp2(2, 2, [1,1]);

// /* INPUT = {
//     "P": [ [[[1,0],[1,0]],[[1,0],[0,0]]], 
//                 [[[1,0],[1,0]],[[0,0],[1,0]]] ], 
//     "Q": [ [[[1,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]],[[1,0],[0,0]]],
//             [[[1,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]],[[0,0],[1,0]]] ]
// } */

// Inputs:
//  P is 2 x 2 x k array where P0 = (x_1, y_1) and P1 = (x_2, y_2) are points in E(Fp2)
//  Q is 2 x 6 x 2 x k array representing point (X, Y) in E(Fp12)
// Assuming (x_1, y_1) != (x_2, y_2)
// Output:
//  Q is 6 x 2 x k array representing element of Fp12 equal to:
//  (y_1 - y_2) X + (x_2 - x_1) Y + (x_1 y_2 - x_2 y_1)
template LineFunctionUnequalFp2(n, k, q) {
    signal input P[2][2][2][k];
    signal input Q[2][6][2][k];

    signal output out[6][2][k];
    var LOGK1 = log_ceil(24*k);
    var LOGK2 = log_ceil(24*k*k);

    component nocarry = SignedLineFunctionUnequalNoCarryFp2(n, k, 2 * n + LOGK1);
    for (var i = 0; i < 2; i++)for(var j = 0; j < 2; j++) {
	    for (var idx = 0; idx < k; idx++) {
            nocarry.P[i][j][0][idx] <== P[i][j][0][idx];
            nocarry.P[i][j][1][idx] <== P[i][j][1][idx];
	    }
    }

    for (var i = 0; i < 2; i++)for(var j = 0; j < 6; j++) {
	    for (var l = 0; l < 2; l++) {
		for (var idx = 0; idx < k; idx++) {
		    nocarry.Q[i][j][l][idx] <== Q[i][j][l][idx];
		}
	    }
    }
    component reduce[6][2];
    for (var i = 0; i < 6; i++) {
        for (var j = 0; j < 2; j++) {
            reduce[i][j] = PrimeReduce(n, k, k - 1, q, 3 * n + LOGK2);
        }

        for (var j = 0; j < 2; j++) {
            for (var idx = 0; idx < 2 * k - 1; idx++) {
                reduce[i][j].in[idx] <== nocarry.out[i][j][idx];
            }
        }	
    }

    // max overflow register size is 3 * k * 2^{3n + log(k)}
    component carry = SignedFp12CarryModP(n, k, 3 * n + LOGK2, q);
    for (var i = 0; i < 6; i++) {
        for (var j = 0; j < 2; j++) {
            for (var idx = 0; idx < k; idx++) {
                carry.in[i][j][idx] <== reduce[i][j].out[idx];
            }
        }
    }
    
    for (var i = 0; i < 6; i++) {
        for (var j = 0; j < 2; j++) {
            for (var idx = 0; idx < k; idx++) {
            out[i][j][idx] <== carry.out[i][j][idx];
            }
        }
    }    
}

// component main { public [P, Q] } = LineFunctionEqualFp2(2, 2, [1,1]);

// /* INPUT = {
//     "P": [[[1,0],[1,0]],[[1,0],[2,0]]], 
//     "Q": [ [[[1,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]],[[1,0],[0,0]]],
//             [[[1,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]],[[0,0],[0,0]],[[0,0],[1,0]]] ]
// } */

// Assuming curve is of form Y^2 = X^3 + b for now (a = 0) for better register bounds 
// Inputs:
//  P is 2 x 2 x k array where P = (x, y) is a point in E(Fp2) 
//  Q is 2 x 6 x 2 x k array representing point (X, Y) in E(Fp12) 
// Output: 
//  out is 6 x 2 x k array representing element of Fp12 equal to:
//  3 x^2 (-X + x) + 2 y (Y - y)
template LineFunctionEqualFp2(n, k, q) {
    signal input P[2][2][k];
    signal input Q[2][6][2][k];

    signal output out[6][2][k];

    var LOGK2 = log_ceil(4*(6*k+1)*k);
    component nocarry = SignedLineFunctionEqualNoCarryFp2(n, k, 3*n + LOGK2);
    for (var i = 0; i < 2; i++) {
        for (var j = 0; j < 2; j ++) {
            for (var idx = 0; idx < k; idx++) {
                nocarry.P[i][j][idx] <== P[i][j][idx];
            }
        }
    }

    for (var i = 0; i < 2; i++) {
        for (var j = 0; j < 6; j++) {
            for (var l = 0; l < 2; l++) {
                for (var idx = 0; idx < k; idx++) {
                    nocarry.Q[i][j][l][idx] <== Q[i][j][l][idx];
                }
            }
        }
    }
    
    var LOGK3 = log_ceil(4*(2*k-1)*(6*k+1)*k);
    component reduce[6][4]; 
    for (var i = 0; i < 6; i++) {
        for (var j = 0; j < 2; j++) {
            reduce[i][j] = PrimeReduce(n, k, 2 * k - 2, q, 4 * n + LOGK3);
        }

        for (var j = 0; j < 2; j++) {
            for (var idx = 0; idx < 3 * k - 2; idx++) {
                reduce[i][j].in[idx] <== nocarry.out[i][j][idx];
            }
        }	
    }

    // max overflow register size is (2k - 1) * (6k+1)* k * 2^{4n}
    component carry = SignedFp12CarryModP(n, k, 4 * n + LOGK3, q);
    for (var i = 0; i < 6; i++) {
        for (var j = 0; j < 2; j++) {
            for (var idx = 0; idx < k; idx++) {
                carry.in[i][j][idx] <== reduce[i][j].out[idx];
            }
        }
    }
    
    for (var i = 0; i < 6; i++) {
        for (var j = 0; j < 2; j++) {
            for (var idx = 0; idx < k; idx++) {
            out[i][j][idx] <== carry.out[i][j][idx];
            }
        }
    }    
}

