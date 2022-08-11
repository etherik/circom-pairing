const { MerkleTree } = require("fixed-merkle-tree");
const ethers = require("ethers");
const { sign, Point } = require("@noble/secp256k1");
const keccak256 = require("keccak256");
const fs = require("fs");
const mimcfs = require("./mimc.js");
const mimc = require("./mimc.js");

const mimcHasher = mimcfs.mimcHash(123);

const fromHexString = (hexString) => new Uint8Array(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

const intToHex = (intString) => ethers.BigNumber.from(intString).toHexString();
const hexStringToBigInt = (hexString) => {
    return Uint8Array_to_bigint(fromHexString(hexString));
};

// bigendian
function bigint_to_Uint8Array(x) {
    var ret = new Uint8Array(32);
    for (var idx = 31; idx >= 0; idx--) {
        ret[idx] = Number(x % 256n);
        x = x / 256n;
    }
    return ret;
}

// bigendian
function Uint8Array_to_bigint(x) {
    var ret = 0n;
    for (var idx = 0; idx < x.length; idx++) {
        ret = ret * 256n;
        ret = ret + BigInt(x[idx]);
    }
    return ret;
}

function bigint_to_array(n, k, x) {
    let mod = 1n;
    for (var idx = 0; idx < n; idx++) {
        mod = mod * 2n;
    }

    let ret = [];
    var x_temp = x;
    for (var idx = 0; idx < k; idx++) {
        ret.push(x_temp % mod);
        x_temp = x_temp / mod;
    }
    return ret;
}

// bigendian
function Uint8Array_to_bigint(x) {
    var ret = 0n;
    for (var idx = 0; idx < x.length; idx++) {
        ret = ret * 256n;
        ret = ret + BigInt(x[idx]);
    }
    return ret;
}

function commitmentComputer(
    voteCount,
    eligibleRoot,
    voterRoot,
    msghash,
    proof
  ) {
    const commitmentInputsAny = [
        voteCount,
        eligibleRoot,
        voterRoot,
        ...msghash,
        ...proof.negalfa1xbeta2.flat(20),
        ...proof.gamma2.flat(20),
        ...proof.delta2.flat(20),
        ...proof.IC.flat(20),
    ];
    const commitmentInputs = commitmentInputsAny.map((x) => x.toString());
    const commitmentInputTypes = [];
    for (var idx = 0; idx < commitmentInputs.length; idx++)
        commitmentInputTypes.push("uint256");

    return ethers.BigNumber.from(
        ethers.utils.soliditySha256(commitmentInputTypes, commitmentInputs)
    ).shr(6).toString();
}
  

function generateMerkleTree(keys) {
    let leafs = keys.map((key) => {
        if (!key) {
            return 0;
        }
        console.log('key', key);
        const wallet = new ethers.Wallet(key);
        return mimcHasher(BigInt(wallet.address));
    })

    console.log('preAddress', keys.map((key) => {
        if (!key) {
            return 0;
        }
        console.log('key', key);
        const wallet = new ethers.Wallet(key);
        return wallet.address;
    }))

    console.log('leafs', leafs);

    const tree = new MerkleTree(22, leafs, { hashFunction: mimcHasher });

    const randproof = tree.path(0);

    console.log("randproof", randproof);

    return tree;
}

async function generateTestCases() {
    const test_cases = [];
    const privkeys = [88549154299169935420064281163296845505587953610183896504176354567359434168161n,
        37706893564732085918706190942542566344879680306879183356840008504374628845468n,
        90388020393783788847120091912026443124559466591761394939671630294477859800601n,
        110977009687373213104962226057480551605828725303063265716157300460694423838923n];

    const rawProof = fs.readFileSync("../../python/fixtures/full-circom-input-0.json");
    const proof = JSON.parse(rawProof);

    for (var idx = 0; idx < privkeys.length; idx++) {
        const proverPrivkey = privkeys[idx];
        const proverPubkey = Point.fromPrivateKey(proverPrivkey);
        const msg = "\x19Ethereum Signed Message:\n83iso58e50c14a4c3018f6053a8731bccea72fd9c0c9658e50c14a4c3018f6053a8731bccea72fd9c0c96";
        const msghash_bigint = Uint8Array_to_bigint(keccak256(msg));
        console.log('msghash_bigint', msghash_bigint);
        const msghash = bigint_to_Uint8Array(msghash_bigint);
        const sig = await sign(msghash, bigint_to_Uint8Array(proverPrivkey), {
            canonical: true,
            der: false,
        });
        const r = sig.slice(0, 32);
        const s = sig.slice(32, 64);
        var r_bigint = Uint8Array_to_bigint(r);
        var s_bigint = Uint8Array_to_bigint(s);
        var r_array = bigint_to_array(64, 4, r_bigint);
        var s_array = bigint_to_array(64, 4, s_bigint);
        var msghash_array = bigint_to_array(64, 4, msghash_bigint);
        console.log('msghash_array', msghash_array);
        // Generate merkle tree and path
        const eligibleTree = generateMerkleTree(privkeys);
        const eligiblePathData = eligibleTree.path(idx);
        const onlyEnabled = privkeys.map((privkey, i) => { return (idx == i || i == 0) ? privkey : 0; });
        console.log("onlyEnabled", onlyEnabled);
        const voterTree = generateMerkleTree(onlyEnabled);
        const voterPathData = voterTree.path(idx);
        console.log("eligiblePathElements", eligiblePathData.pathElements);
        console.log("voterPathElements", voterPathData.pathElements);
        console.log("msghash", msghash);

        let voteCount = 0;
        for (const elem of onlyEnabled) {
            voteCount += (elem != 0) ? 1 : 0;
        }

        const pubCommit = commitmentComputer(voteCount, eligiblePathData.pathRoot, voterPathData.pathRoot, msghash_array.map((x) => x.toString()), proof);

        const json = JSON.stringify(
            {
                semiPublicCommitment: pubCommit,
                voteCount: voteCount,
                eligibleRoot: eligiblePathData.pathRoot,
                voterRoot: voterPathData.pathRoot,
                r: r_array.map((x) => x.toString()),
                s: s_array.map((x) => x.toString()),
                msghash: msghash_array.map((x) => x.toString()),
                pubkey: [bigint_to_array(64, 4, proverPubkey.x).map((x) => x.toString()), bigint_to_array(64, 4, proverPubkey.y).map((x) => x.toString())],
                eligiblePathElements: eligiblePathData.pathElements,
                voterPathElements: voterPathData.pathElements,
                pathIndices: voterPathData.pathIndices,
                ...proof,
            },
            null,
            "\t"
        );
        console.log(json);
        fs.writeFile("./input_" + idx.toString() + ".json", json, "utf8", function (err) {
            if (err) throw err;
            console.log("Saved!");
        });
    }
}

generateTestCases();