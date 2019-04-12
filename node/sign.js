var test_sk = '-----BEGIN PRIVATE KEY-----\n'
+ 'MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgBe+hD0dANH1UonOwQxqe\n'
+ 'Fvc/J/C+8jTsqOtYSiQ+OamhRANCAAQ7U312c15p98EigrRri9+gp0BXvzSdhNUC\n'
+ 'B2eSywdObeYu702dkOgHQ8rzpkUdj4TDMjItDR7fHshmfgaL3hWa\n'
+ '-----END PRIVATE KEY-----\n';
    
var test_pk = '-----BEGIN CERTIFICATE-----\n'
+ 'MIIC4zCCAUugAwIBAgIRAJbcGDlLWBv36VTBSifZ90owDQYJKoZIhvcNAQELBQAw\n'
+ 'PTEVMBMGA1UEAxMMLy8vLy8vLy8vLzg9MQswCQYDVQQGEwJLUjEXMBUGA1UEChMO\n'
+ 'R3J1dXQgTmV0d29ya3MwHhcNMTkwMjI2MDIzNDUyWhcNMjAwMjI2MDIzNDUyWjAR\n'
+ 'MQ8wDQYDVQQDEwZURVNUQ04wVjAQBgcqhkjOPQIBBgUrgQQACgNCAAQ7U312c15p\n'
+ '98EigrRri9+gp0BXvzSdhNUCB2eSywdObeYu702dkOgHQ8rzpkUdj4TDMjItDR7f\n'
+ 'HshmfgaL3hWao1gwVjAhBgNVHQ4EGgQY0wM+4GWLF2ySLHkLMoBzTbg3MuAzbuy3\n'
+ 'MAwGA1UdEwEB/wQCMAAwIwYDVR0jBBwwGoAYGCaqNIlvb/99LRAlk5JGHBjYKebe\n'
+ 'jLP9MA0GCSqGSIb3DQEBCwUAA4IBgQAU2HtzzCIqlh4DvHbtcH6duH/nAPEyXmk1\n'
+ '4NXFgbQQjQTlmRAHzpjXcRxaIjpesy6iOzTR7Rf5Oo1nDj9fXks8wMdTdruajqTv\n'
+ '7NA2Wd4d6qgM30i2ss/ebJm1pSTL04hQM6XvEvyvYt7lgVV/GXvzgUoW8GDXSw3X\n'
+ '3upTGlDJEuLlILzFskOBYReKXhen6WjEL1qecXw9FNHpvzuzRZdPUQkeJX9cZZJz\n'
+ 'F1iT28uBYX3YFDGW4x2THGxZOqp3ssdvuC/oTerBdrUTr8JiYIoVjy42StzWI6aC\n'
+ 'vyqJbkalyPt5YgVlPtFy+Adv+mcUpQ9i8sYlfE3iUKxeJnMKpGgvjg8ppThVpVBt\n'
+ 'TikN67sThXbzdOcEBrp1HksShTYgDYQ0go7zOcrM/tZJoSOsGrYL465luqAADuJR\n'
+ 'U6sMCFVCluwL4+tP+pNyf79B2dwZdmtO90hOEODR7ue9qOGrTT2zmbgWpY1VnPD/\n'
+ 'DocbVvQtIp+Hz4+8lSHaDy2N9TThUdo=\n'
+ '-----END CERTIFICATE-----\n';

const sjcl = require('sjcl');
const EC = require('elliptic').ec;
const curve = new EC('secp256k1');
const BN = require('bn.js');
const crypto = require('crypto');
const asn1 = require('asn1.js');

function hash_point(point) {
    var hash = crypto.createHash('sha256');
    var point_x_str = point.x.toString(16);
    hash.update(point_x_str.toUpperCase());
    var point_y_str = point.y.toString(16);
    hash.update(point_y_str.toUpperCase());
    var hex = hash.digest('hex');
    var bigint = new BN(new BN(hex, 16).toString(10));
    return bigint;
}

// load from pem
var ECPrivateKey = asn1.define('ECPrivateKey', function() {
    this.seq().obj(
      this.key('version').int().def(1),
      this.key('algorithm').seq().obj(
        this.key("id").objid(),
        this.key("curve").objid()
      ),
      this.key('privateKey').octstr()
      )
  });

// sk_pem -> bigint_sk;
var temp_pk = "";
function pemToHex(sk_pem) {
    let hex_sk = "";
    const out = ECPrivateKey.decode(sk_pem, 'pem', {label : 'Private Key'});
    let temp = out.privateKey.toString('hex');

    for(var i = 14; i < 78; ++i) {
        hex_sk += temp[i];
    }

    let keyPair = curve.keyFromPrivate(hex_sk);
    let pubKey = keyPair.getPublic(); // return bigint

    let bigint_sk = curve.keyFromPrivate(hex_sk, "hex").getPrivate().toString(10);
    temp_pk = pubKey;

    return bigint_sk;
}

function hash_point_msg(point, msg) {
    var hash = crypto.createHash('sha256');
    var x_str = point.x.toString(16);
    hash.update(x_str.toUpperCase());
    var y_str = point.y.toString(16);
    hash.update(y_str.toUpperCase());
    hash.update(msg);
    var hex = hash.digest('hex');
    var bigint = new BN(new BN(hex, 16).toString(10));
    return bigint;
}

function sign(sk_pem, msg) {
    var r_str = sjcl.bn.random(sjcl.ecc.curves.k256.r).toString();
    var r = '';

    for(var i = 2; i < 66; ++i) {
        r += r_str[i];
    }

    var bigint_r = new BN(new BN(r, 10).toString(10));
    // console.log(`r : ${bigint_r}`);

    var a = curve.g.mul(bigint_r);
    var bigint_d = hash_point(a);
    console.log(`d : ${bigint_d}`);

    var bigint_sk = new BN(pemToHex(sk_pem));
    var pk = temp_pk;
    
    var bigint_e = hash_point_msg(pk, msg);
    // console.log(`e : ${bigint_e}`);

    var r_mul_d = new BN(bigint_r.mul(bigint_d).umod(curve.n));
    var e_mul_sk = new BN(bigint_e.mul(bigint_sk).umod(curve.n));
    var z = new BN(r_mul_d.sub(e_mul_sk)).umod(curve.n).toString();
    console.log(`z: ${z}`);

    return [bigint_d, z];
}