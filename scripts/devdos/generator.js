const { MerkleTree } = require("fixed-merkle-tree");
const ethers = require("ethers");
const { sign, Point } = require("@noble/secp256k1");
const keccak256 = require("keccak256");
const fs = require("fs");
const mimcfs = require("./mimc.js");
const mimc = require("./mimc.js");
const privateKeyToAddress = require('ethereum-private-key-to-address');
const { exit } = require("process");

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

function commitmentComputer(proof) {
        return mimcHasher(
            ...proof.negalfa1xbeta2.flat(20),
            ...proof.gamma2.flat(20),
            ...proof.delta2.flat(20),
            ...proof.IC.flat(20),
            )
}


async function generateTestCases() {
    const test_cases = [];
    const privkeys = [88549154299169935420064281163296845505587953610183896504176354567359434168161n,
        98855089179455197279583810751921776194429729927600246755329568052735742445312n,
        37706893564732085918706190942542566344879680306879183356840008504374628845468n,
        90388020393783788847120091912026443124559466591761394939671630294477859800601n,
        110977009687373213104962226057480551605828725303063265716157300460694423838923n];

    const ethAddresses = privkeys.map((x) => privateKeyToAddress(intToHex(x.toString())).toLowerCase());
    console.log("ethAddresses", ethAddresses);

    for (var idx = 0; idx < privkeys.length - 1; idx++) {
        const rawProof = fs.readFileSync('../../python/fixtures/full-circom-input-' + idx + '.json');
        const proof = JSON.parse(rawProof);

        const sourcePrivkey = privkeys[idx];
        const sourcePubkey = Point.fromPrivateKey(sourcePrivkey);
        
        const sinkAddress = ethAddresses[idx + 1].toLowerCase();
        console.log("sinkAddress", sinkAddress);

        const msg = "\x19Ethereum Signed Message:\n57ETHdos friend: " + sinkAddress;

        const msghash_bigint = Uint8Array_to_bigint(keccak256(msg));
        const msghash = bigint_to_Uint8Array(msghash_bigint);
        const sig = await sign(msghash, bigint_to_Uint8Array(sourcePrivkey), {
            canonical: true,
            der: false,
        });
        const r = sig.slice(0, 32);
        const s = sig.slice(32, 64);
        var r_bigint = Uint8Array_to_bigint(r);
        var s_bigint = Uint8Array_to_bigint(s);
        var r_array = bigint_to_array(64, 4, r_bigint);
        var s_array = bigint_to_array(64, 4, s_bigint);

        const semiPubCommit = commitmentComputer(proof);

        const originator = hexStringToBigInt(ethAddresses[0]);

        // copy proof without pubInput
        const proofNoPubInp = {}
        for (const [k, v] of Object.entries(proof)) {
            if (k !== "pubInput") {
                proofNoPubInp[k] = v;
            }
        }

        const json = JSON.stringify(
            {
                semiPublicCommitment: semiPubCommit,
                degree: idx + 1,
                originator: originator.toString(),
                sinkAddress: hexStringToBigInt(sinkAddress).toString(),
                r: r_array.map((x) => x.toString()),
                s: s_array.map((x) => x.toString()),
                sourcePubkey: [bigint_to_array(64, 4, sourcePubkey.x).map((x) => x.toString()), bigint_to_array(64, 4, sourcePubkey.y).map((x) => x.toString())],
                ...proofNoPubInp,
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