import wif from 'wif';
import { publicKeyCreate, sign as ecdsaSign, verify as ecdsaVerify } from 'secp256k1';
import { randomBytes, createHash, createECDH, createCipheriv, createDecipheriv } from 'crypto';
import { clone } from "lodash";
import chash from "./chash";

var STRING_JOIN_CHAR = "\x00";

export function deriveSharedSecret(ecdh, peerB64Pubkey) {
  const sharedSecretSrc = ecdh.computeSecret(peerB64Pubkey, 'base64');
  return createHash('sha256')
    .update(sharedSecretSrc)
    .digest()
    .slice(0, 16);
}

export function createEncryptedPackage(json, recipientDevicePubkey) {
  const text = JSON.stringify(json);
  const ecdh = createECDH('secp256k1');
  const senderEphemeralPubkey = ecdh.generateKeys('base64', 'compressed');
  const sharedSecret = deriveSharedSecret(ecdh, recipientDevicePubkey); // Buffer
  // we could also derive iv from the unused bits of ecdh.computeSecret() and save some bandwidth
  const iv = randomBytes(12); // 128 bits (16 bytes) total, we take 12 bytes for random iv and leave 4 bytes for the counter
  const cipher = createCipheriv('aes-128-gcm', sharedSecret, iv);
  // under browserify, encryption of long strings fails with Array buffer allocation errors, have to split the string into chunks
  let arrChunks = [];
  const CHUNK_LENGTH = 2003;
  for (let offset = 0; offset < text.length; offset += CHUNK_LENGTH) {
    arrChunks.push(
      // @ts-ignore
      cipher.update(text.slice(offset, Math.min(offset + CHUNK_LENGTH, text.length)), 'utf8')
    );
  }
  // @ts-ignore
  arrChunks.push(cipher.final());
  const encryptedMessageBuf = Buffer.concat(arrChunks);

  const encryptedMessage = encryptedMessageBuf.toString('base64');
  const authtag = cipher.getAuthTag();
  // this is visible and verifiable by the hub
  return {
    encrypted_message: encryptedMessage,
    iv: iv.toString('base64'),
    authtag: authtag.toString('base64'),
    dh: {
      sender_ephemeral_pubkey: senderEphemeralPubkey,
      recipient_ephemeral_pubkey: recipientDevicePubkey
    }
  };
}

export function decryptPackage(objEncryptedPackage, objMyTempDeviceKey) {
  const priv_key = objMyTempDeviceKey.priv;
  if (objMyTempDeviceKey.use_count) objMyTempDeviceKey.use_count++;
  else objMyTempDeviceKey.use_count = 1;

  const ecdh = createECDH('secp256k1');
  
  if (process.browser) ecdh.generateKeys('base64', 'compressed');
  ecdh.setPrivateKey(priv_key);
  const shared_secret = deriveSharedSecret(ecdh, objEncryptedPackage.dh.sender_ephemeral_pubkey);
  const iv = Buffer.from(objEncryptedPackage.iv, 'base64');
  const decipher = createDecipheriv('aes-128-gcm', shared_secret, iv);
  const authtag = Buffer.from(objEncryptedPackage.authtag, 'base64');
  decipher.setAuthTag(authtag);
  const enc_buf = Buffer.from(objEncryptedPackage.encrypted_message, 'base64');

  
  let arrChunks = [];
  const CHUNK_LENGTH = 4096;
  for (let offset = 0; offset < enc_buf.length; offset += CHUNK_LENGTH) {
    arrChunks.push(
      // @ts-ignore
      decipher.update(enc_buf.slice(offset, Math.min(offset + CHUNK_LENGTH, enc_buf.length)))
    );
  }
  const decrypted1 = Buffer.concat(arrChunks);
  let decrypted2;
  try {
    decrypted2 = decipher.final();
  } catch (e) {
    return console.log('Failed to decrypt package: ' + e);
  }

  const decrypted_message_buf = Buffer.concat([decrypted1, decrypted2]);
  const decrypted_message = decrypted_message_buf.toString('utf8');
  const json = JSON.parse(decrypted_message);
  if (json.encrypted_package) {
    // strip another layer of encryption
    return decryptPackage(json.encrypted_package, objMyTempDeviceKey);
  } else return json;
}

export function createObjDeviceKey(priv) {
  try {
    return { priv, pub_b64: publicKeyCreate(priv, true).toString('base64') };
  } catch (e) {
    console.log("createObjDeviceKey err ", e)
  }
}

export function toWif(privateKey, testnet) {
  const version = testnet ? 239 : 128;
  return wif.encode(version, privateKey, false);
}

export function fromWif(string, testnet) {
  const version = testnet ? 239 : 128;
  return wif.decode(string, version);
}

export function sign(hash, privateKey) {
  try{
    const res = ecdsaSign(hash, privateKey);
    return res.signature.toString('base64');
  } catch (e) {
    console.error("sign error", e)
  }
  
}

export function verify(hash, b64Sig, b64Pubkey) {
  try {
    const signature = new Buffer(b64Sig, 'base64');
    return ecdsaVerify(hash, signature, new Buffer(b64Pubkey, 'base64'));
  } catch (e) {
    return false;
  }
}

export const generatePaymentMessage = (objPaymentRequest) => {
  const paymentJson = JSON.stringify(objPaymentRequest);
  return Buffer.from(paymentJson).toString('base64');
}

function cleanNullsDeep(obj) {
  Object.keys(obj).forEach(function (key) {
    if (obj[key] === null)
      delete obj[key];
    else if (typeof obj[key] === 'object') // array included
      cleanNullsDeep(obj[key]);
  });
}

export function getDeviceMessageHashToSign(objDeviceMessage) {
  var objNakedDeviceMessage = clone(objDeviceMessage);
  delete objNakedDeviceMessage.signature;
  cleanNullsDeep(objNakedDeviceMessage); // device messages have free format and we can't guarantee absence of malicious fields
  return createHash("sha256").update(getSourceString(objNakedDeviceMessage), "utf8").digest();
}

export function getDeviceAddress(b64_pubkey) {
  return ('0' + getChash160(b64_pubkey));
}

function getChash160(obj) {
  return chash.getChash160(getSourceString(obj));
}

export function getSourceString(obj) {
  var arrComponents = [];
  function extractComponents(variable) {
    if (variable === null)
      throw Error("null value in " + JSON.stringify(obj));
    switch (typeof variable) {
      case "string":
        arrComponents.push("s", variable);
        break;
      case "number":
        arrComponents.push("n", variable.toString());
        break;
      case "boolean":
        arrComponents.push("b", variable.toString());
        break;
      case "object":
        if (Array.isArray(variable)) {
          if (variable.length === 0)
            throw Error("empty array in " + JSON.stringify(obj));
          arrComponents.push('[');
          for (var i = 0; i < variable.length; i++)
            extractComponents(variable[i]);
          arrComponents.push(']');
        }
        else {
          var keys = Object.keys(variable).sort();
          if (keys.length === 0)
            throw Error("empty object in " + JSON.stringify(obj));
          keys.forEach(function (key) {
            if (typeof variable[key] === "undefined")
              throw Error("undefined at " + key + " of " + JSON.stringify(obj));
            arrComponents.push(key);
            extractComponents(variable[key]);
          });
        }
        break;
      default:
        throw Error("hash: unknown type=" + (typeof variable) + " of " + variable + ", object: " + JSON.stringify(obj));
    }
  }

  extractComponents(obj);
  return arrComponents.join(STRING_JOIN_CHAR);
}