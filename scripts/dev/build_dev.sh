#!/bin/bash

PHASE1=../../circuits/powersOfTau28_hez_final_25.ptau
BUILD_DIR=../../build/dev
CIRCUIT_NAME=dev

if [ -f "$PHASE1" ]; then
    echo "Found Phase 1 ptau file"
else
    echo "No Phase 1 ptau file found. Exiting..."
    exit 1
fi

if [ ! -d "$BUILD_DIR" ]; then
    echo "No build directory found. Creating build directory..."
    mkdir "$BUILD_DIR"
fi

echo $PWD

echo "****COMPILING CIRCUIT****"
start=`date +%s`
#circom "$CIRCUIT_NAME".circom --O0 --c --output "$BUILD_DIR"
circom "$CIRCUIT_NAME".circom --O1 --r1cs --sym --c --output "$BUILD_DIR"
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****COMPILING C++ WITNESS GENERATION CODE****"
start=`date +%s`
cd "$BUILD_DIR"/"$CIRCUIT_NAME"_cpp 
make
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****VERIFYING WITNESS****"
start=`date +%s`
./"$CIRCUIT_NAME" ../../../scripts/"$CIRCUIT_NAME"/input_"$CIRCUIT_NAME".json ../witness.wtns
end=`date +%s`
echo "DONE ($((end-start))s)"

# cd ..
# npx snarkjs wej witness.wtns witness.json

echo "****GENERATING ZKEY 0****"
start=`date +%s`
/data/node/out/Release/node --trace-gc --trace-gc-ignore-scavenger --max-old-space-size=2048000 --initial-old-space-size=2048000 --no-global-gc-scheduling --no-incremental-marking --max-semi-space-size=1024 --initial-heap-size=2048000 --expose-gc /data/snarkjs/cli.js zkey new "$CIRCUIT_NAME".r1cs "$PHASE1" "$CIRCUIT_NAME"_0.zkey -v
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****CONTRIBUTE TO PHASE 2 CEREMONY****"
start=`date +%s`
/data/node/out/Release/node /data/snarkjs/cli.js zkey contribute -verbose "$CIRCUIT_NAME"_0.zkey "$CIRCUIT_NAME".zkey -n="First phase2 contribution" -e="some random text 5555"
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****VERIFYING FINAL ZKEY****"
start=`date +%s`
/data/node/out/Release/node --trace-gc --trace-gc-ignore-scavenger --max-old-space-size=2048000 --initial-old-space-size=2048000 --no-global-gc-scheduling --no-incremental-marking --max-semi-space-size=1024 --initial-heap-size=2048000 --expose-gc /data/snarkjs/cli.js zkey verify -verbose "$CIRCUIT_NAME".r1cs "$PHASE1" "$CIRCUIT_NAME".zkey
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****EXPORTING VKEY****"
start=`date +%s`
/data/node/out/Release/node /data/snarkjs/cli.js zkey export verificationkey "$CIRCUIT_NAME".zkey vkey.json -v
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****GENERATING PROOF FOR SAMPLE INPUT****"
start=`date +%s`
/data/rapidsnark/build/prover "$CIRCUIT_NAME".zkey witness.wtns proof.json public.json
end=`date +%s`
echo "DONE ($((end-start))s)"

echo "****VERIFYING PROOF FOR SAMPLE INPUT****"
start=`date +%s`
/data/node/out/Release/node /data/snarkjs/cli.js groth16 verify vkey.json public.json proof.json -v
end=`date +%s`
echo "DONE ($((end-start))s)"
