'use strict';
import { sha1 } from 'digest';

// WPA2 PBKDF2-HMAC-SHA1，4096 次，32 字节；只用锁定的原生 digest。
function psk(password, ssid) {
 let inner = '', outer = '';
 for (let i = 0; i < 64; i++) {
  let n = i < length(password) ? ord(password, i) : 0;
  inner += chr(n ^ 0x36); outer += chr(n ^ 0x5c);
 }
 function hmac(data) { return hexdec(sha1(outer + hexdec(sha1(inner + data)))); }
 let result = '';
 for (let block = 1; block <= 2; block++) {
  let u = hmac(ssid + chr(0, 0, 0, block)), t = [];
  for (let i = 0; i < 20; i++) push(t, ord(u, i));
  for (let round = 1; round < 4096; round++) {
   u = hmac(u);
   for (let i = 0; i < 20; i++) t[i] ^= ord(u, i);
  }
  for (let n in t) result += chr(n);
 }
 return hexenc(substr(result, 0, 32));
}
// 解码 supplicant printf_encode 控制协议，保持 UTF-8 原始字节。
function decode_ssid(value) {
 let result = '';
 for (let i = 0; i < length(value); i++) {
  let ch = substr(value, i, 1);
  if (ch != '\\' || i + 1 >= length(value)) { result += ch; continue; }
  let next = substr(value, i + 1, 1);
  if (next == 'x') {
   let decoded = hexdec(substr(value, i + 2, 2), '');
   if (decoded != null && length(decoded) == 1) { result += decoded; i += 3; continue; }
  }
  let escapes = { n: '\n', r: '\r', t: '\t', e: chr(27), '\\': '\\', '"': '"' };
  if (next in escapes) { result += escapes[next]; i++; }
  else result += ch;
 }
 return result;
}
return { psk, decode_ssid };
