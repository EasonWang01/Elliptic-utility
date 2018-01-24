const ecc = require('../src/Elliptic').ec
const BigInteger = require('../src/Biginteger').BigInteger

const crypto = require('crypto');
const base58 = require('bs58')

const parent_xkey = 'xprv9s21ZrQH143K3Cbeqiamwsa6TBF3jEYsLKbYTMF1zN2qFz7hSPWtdDe1q8EmF1e4eYjMPt5zz83wgJK6WhHuKpWFjtitVJpvWVRhSkDxAoE';

// 解碼xkey
function decode_xkey(data) {
	if (typeof (data) == 'string') {
		var decoded = base58.decode(data)
		if (decoded.length == 82) {
			var decoded_checksum = decoded.slice(78, 82);
			// 重新檢查checksum
			doubleSHA_bytes = crypto.createHash('sha256').update(
				crypto.createHash('sha256').update(Buffer.from(decoded.slice(0, 78))).digest()
			).digest();
			if (doubleSHA_bytes[0] == decoded_checksum[0]
				&& doubleSHA_bytes[1] == decoded_checksum[1]
				&& doubleSHA_bytes[2] == decoded_checksum[2]
				&& doubleSHA_bytes[3] == decoded_checksum[3]) {
				let _bytes = decoded.slice(0, 78);
				return _bytes
			} else {
				console.log('checksum not match');
			}
		}
	}
}
bytes = decode_xkey(parent_xkey)

// 將base58 decode後的bytes 分解為六部分共78bytes
let ser = {
	version: bytes.slice(0, 4),
	depth: bytes.slice(4, 5),
	parent_fingerprint: bytes.slice(5, 9),
	child_index: bytes.slice(9, 13),
	chain_code: bytes.slice(13, 45),
	key_bytes: bytes.slice(45, 78)
};


//  如果xkey 為 xprv 則解碼出private key 並利用橢圓曲線產生public key 
if (ser.key_bytes[0] === 0) {
	// private key
	private_key = bytesToHex(ser.key_bytes.slice(1, 33));
	// 從私鑰產生公鑰
	const ecdh = crypto.createECDH('secp256k1');
	const Uncompress_publickey = ecdh.setPrivateKey(Buffer.from(hexToDecimalArray(private_key))).getPublicKey('hex')
	// 變為壓縮的公鑰
	function Compress_public(_pubkey) {
		return (
			_pubkey.slice(-1) % 2 === 0
				? "02" + _pubkey.slice(2, 66)
				: "03" + _pubkey.slice(2, 66)
		)
	}
	public_key = Compress_public(Uncompress_publickey);
} else if (ser.key_bytes[0] === 2 || ser.key_bytes[0] === 3) {
	//  如果為 xkey 為 xpub 則指產生public key
	public_key = bytesToHex(ser.key_bytes);
} else {
	console.log('invalid key');
}

let index = "00000000"; // 這邊預設都是只產生index為0的child
let HMAC_data = public_key + index;
let HMAC_key = ser.chain_code;

// 使用 parent 之 public_key 與 chain code 產生 HMAC_SHA512雜湊
HMAC_SHA512 = crypto.createHmac('sha512', Buffer.from(HMAC_key, 'hex'))
	.update(Buffer.from(HMAC_data, 'hex')).digest('hex');
// il與ir為HMAC-SHA512 雜湊後切分左側與右側
let il = new BigInteger(HMAC_SHA512.slice(0, 64), 16);
let ir = HMAC_SHA512.slice(64, 128);

// 相關橢圓曲線參數使用secp256k1
EllipticCurve = ec;
var ecparams = ec.getSECCurveByName("secp256k1");
var curve = ecparams.getCurve();

if (parent_xkey.slice(0, 4) === 'xprv') {
	// 使用父 private_key 計算derive 出的 下一層 child private key 與 child public key
	k = il.add(new BigInteger([0].concat(hexToDecimalArray(private_key)))).mod(ecparams.getN());
	child_privatekey = bytesToHex(k.toByteArrayUnsigned());
	// pubkey = coinjs.newPubkey(key);
	// 從私鑰產生公鑰
	const ecdh = crypto.createECDH('secp256k1');
	const Uncompress_publickey = ecdh.setPrivateKey(Buffer.from(hexToDecimalArray(child_privatekey))).getPublicKey('hex')
	child_publickey = Compress_public(Uncompress_publickey);

} else if (parent_xkey.slice(0, 4) === 'xpub') {
	//  使用 父 public_key 計算 derive 出的 下一層 child public key
	q = ecparams.curve.decodePointHex(public_key);
	var curvePt = ecparams.getG().multiply(il).add(q);
	var x = curvePt.getX().toBigInteger();
	var y = curvePt.getY().toBigInteger();
	var x_decimalBytes = EllipticCurve.integerToBytes(x, 32);// toByteArrayUnsigned 與 integerToBytes 類似
	var y_decimalBytes = EllipticCurve.integerToBytes(y, 32);

	// 	轉為壓縮公鑰
	var publicKeyBytesCompressed = x_decimalBytes
	if (y_decimalBytes[y_decimalBytes.length - 1] % 2 === 0) {
		publicKeyBytesCompressed.unshift(0x02)
	} else {
		publicKeyBytesCompressed.unshift(0x03)
	}
	// 從 bytes格式轉為Hex字串格式的child public key
	child_publickey = bytesToHex(publicKeyBytesCompressed)
} else {
	console.log('Not a valid xkey');
}


// 用 parent 的 public key 算出 finger_print
var RIPEMD160 = require('ripemd160')
let sha256 = crypto.createHash('sha256').update(Buffer.from(public_key, 'hex')).digest('hex')
let fingerprint = hexToDecimalArray(new RIPEMD160().update(Buffer.from(sha256, 'hex')).digest('hex')).slice(0, 4);


// 4 bytes version
// 0x0488B21E mainnet public，
// 0x0488ADE4 mainnet private，
// 0x043587CF testnet public，
// 0x04358394 testnet private
const mainnet_prv = '0x0488ADE4';
const mainnet_pub = '0x0488b21e';

// 之後轉為xpub
var child_index = [0, 0, 0, 0] // 這邊預設產生index為0的child

function derive(type, _) {
	let _bytes = generate_xkey(type);
	checksum = crypto.createHash('sha256').update(Buffer.from(_bytes)).digest()
	checksum = crypto.createHash('sha256').update(checksum).digest().slice(0, 4)
	checksumArray = []
	checksum.forEach(buf => {
		checksumArray.push(buf)
	})
	_bytes = _bytes.concat(checksumArray)
	let xkey = base58.encode(_bytes)
	console.log(_)
	console.log(xkey)
}

derive(mainnet_pub, '--xPub--');
if (parent_xkey.slice(0, 4) === 'xprv') {
	// 只有在輸入為xprv時才會產生 child xprv
	derive(mainnet_prv, '--xPrv--');
}

/////////////////////////////////////////////

function generate_xkey(_keyType) {
	return (
		[...hexToDecimalArray(_keyType),
			1,  //depth
		...fingerprint,
		...child_index, // child_index
		...hexToDecimalArray(ir), // chain code
		_keyType === mainnet_prv ? 0 : null, // 如果為xPrv要加上0
		...hexToDecimalArray(_keyType === mainnet_prv ? child_privatekey : child_publickey), // key
		].filter(n => n !== null) // 將 null 元素移除
	)
}

function bytesToHex(byteArray) {
	let _s = '';
	byteArray.forEach(byte => {
		_s += byte.toString('16').length === 1
			? `0${byte.toString('16')}`
			: byte.toString('16')
	})
	return _s
}
function hexToDecimalArray(s) {
	if (s[0] + s[1] === '0x') {
		s = s.replace('0x', '');
	}
	let c = [];
	for (let i = 0; i < s.length - 1; i += 2) {
		c.push(parseInt(`${s[i] + s[i + 1]}`, 16));
	}
	return c;
}

