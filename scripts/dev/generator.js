const MerkleTree = require("fixed-merkle-tree");
const ethers = require("ethers");
const { sign, Point } = require("@noble/secp256k1");
const keccak256 = require("keccak256");
const fs = require("fs");
const mimcfs = require("./mimc.js");

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

function bigint_to_tuple(x) {
    // 2 ** 86
    let mod = 77371252455336267181195264n;
    let ret = [0n, 0n, 0n];

    var x_temp = x;
    for (var idx = 0; idx < 3; idx++) {
        ret[idx] = x_temp % mod;
        x_temp = x_temp / mod;
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

function generateMerkleTree(keys) {
    let leafs = keys.map((key) => {
        if (key == undefined) {
            return 0;
        }
        const wallet = new ethers.Wallet(key);
        return mimcfs.mimcHash(123)(BigInt(wallet.address));
    })

    const tree = new MerkleTree(5, leafs, { hashFunction: mimcfs.mimcHash(123) });

    return tree;
}

async function generateTestCases() {
    // privkey, msghash, pub0, pub1
    const test_cases = [];
    const privkeys = [
        BigInt("0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"),
        88549154299169935420064281163296845505587953610183896504176354567359434168161n,
        90388020393783788847120091912026443124559466591761394939671630294477859800601n,
        BigInt("0x4d5db4107d237df6a3d58ee5f70ae63d73d7658d4026f2eefd2f204c81682cb7"),
    ];

    for (var idx = 0; idx < privkeys.length; idx++) {
        const proverPrivkey = proverPrivkeys[idx];
        const proverPubkey = Point.fromPrivateKey(proverPrivkey);
        const msg = "im a teapot";
        const msghash_bigint = Uint8Array_to_bigint(keccak256(msg));
        const msghash = bigint_to_Uint8Array(msghash_bigint);
        const sig = await sign(msghash, bigint_to_Uint8Array(proverPrivkey), {
            canonical: true,
            der: false,
        });
        const r = sig.slice(0, 32);
        const s = sig.slice(32, 64);
        var r_bigint = Uint8Array_to_bigint(r);
        var s_bigint = Uint8Array_to_bigint(s);
        var r_array = bigint_to_array(86, 3, r_bigint);
        var s_array = bigint_to_array(86, 3, s_bigint);
        var msghash_array = bigint_to_array(86, 3, msghash_bigint);
        const wallet = new ethers.Wallet(privkeys[idx]);
        const hexAddr = wallet.address.slice(2, wallet.address.length);

        // Generate merkle tree and path
        const fullTree = generateMerkleTree(privkeys);
        const { eligiblePathElements, pathIndices } = tree.path(idx);

        
        console.log("pathElements", pathElements);
        console.log("pathIndices", pathIndices);
        const mimcleaves = mimcfs.mimcHash(123)(treeLeaf, BigInt(pathElements[0]));
        console.log("mimcleaves", mimcleaves);
        // for (const sister in pathElements) {
        //   pathElements[sister] = intToHex(pathElements[sister]);
        // }
        console.log("root", tree.root());
        console.log("_layers", tree._layers);
        console.log("msghash", msghash);

        const json = JSON.stringify(
            {
                root: tree.root(),
                r: r_array.map((x) => x.toString()),
                s: s_array.map((x) => x.toString()),
                msghash: msghash_array.map((x) => x.toString()),
                pubkey: [bigint_to_tuple(proverPubkey.x).map((x) => x.toString()), bigint_to_tuple(proverPubkey.y).map((x) => x.toString())],
                pathElements: pathElements,
                pathIndices: pathIndices,
                publicClaimerAddress: hexStringToBigInt(claimerHexAddress).toString(10),
                privateClaimerAddress: hexStringToBigInt(claimerHexAddress).toString(10),
                nullifierHash: nullifierHash.toString(),
            },
            null,
            "\t"
        );
        console.log(json);
        fs.writeFile("./circuits/airdrop/inputs/input_" + idx.toString() + ".json", json, "utf8", function (err) {
            if (err) throw err;
            console.log("Saved!");
        });
    }
}

generateTestCases();