/*
 A JavaScript implementation of the SHA family of hashes, as
 defined in FIPS PUB 180-2 as well as the corresponding HMAC implementation
 as defined in FIPS PUB 198a

 Copyright Brian Turek 2008-2015
 Distributed under the BSD License
 See http://caligatio.github.com/jsSHA/ for more information

 Several functions taken from Paul Johnston
*/
'use strict';(function(I){function w(p,c,b){var a=0,e=[],g=0,f,h,l,m,n,u,r,q=!1,k=[],t=[],v,z=!1;b=b||{};f=b.encoding||"UTF8";v=b.numRounds||1;l=A(c,f);if(v!==parseInt(v,10)||1>v)throw Error("numRounds must a integer >= 1");u=function(c,b){return B(c,b,p)};r=function(c,b,d,g){var e;c=c.slice();var a=g.slice();if("SHA-384"===p||"SHA-512"===p)e=(b+129>>>10<<5)+31,g=32;else throw Error("Unexpected error in SHA-2 implementation");for(;c.length<=e;)c.push(0);c[b>>>5]|=128<<24-b%32;c[e]=b+d;d=c.length;
for(b=0;b<d;b+=g)a=B(c.slice(b,b+g),a,p);if("SHA-384"===p)c=[a[0].a,a[0].b,a[1].a,a[1].b,a[2].a,a[2].b,a[3].a,a[3].b,a[4].a,a[4].b,a[5].a,a[5].b];else if("SHA-512"===p)c=[a[0].a,a[0].b,a[1].a,a[1].b,a[2].a,a[2].b,a[3].a,a[3].b,a[4].a,a[4].b,a[5].a,a[5].b,a[6].a,a[6].b,a[7].a,a[7].b];else throw Error("Unexpected error in SHA-2 implementation");return c};if("SHA-384"===p)n=1024,m=384;else if("SHA-512"===p)n=1024,m=512;else throw Error("Chosen SHA variant is not supported");h=x(p);this.setHMACKey=function(c,
b,d){var g;if(!0===q)throw Error("HMAC key already set");if(!0===z)throw Error("Cannot set HMAC key after calling update");f=(d||{}).encoding||"UTF8";b=A(b,f)(c);c=b.binLen;b=b.value;g=n>>>3;d=g/4-1;if(g<c/8){for(b=r(b,c,0,x(p));b.length<=d;)b.push(0);b[d]&=4294967040}else if(g>c/8){for(;b.length<=d;)b.push(0);b[d]&=4294967040}for(c=0;c<=d;c+=1)k[c]=b[c]^909522486,t[c]=b[c]^1549556828;h=u(k,h);a=n;q=!0};this.update=function(c){var b,p,d,f=0,m=n>>>5;b=l(c,e,g);c=b.binLen;p=b.value;b=c>>>5;for(d=0;d<
b;d+=m)f+n<=c&&(h=u(p.slice(d,d+m),h),f+=n);a+=f;e=p.slice(f>>>5);g=c%n;z=!0};this.getHash=function(c,b){var d,f,n,l;if(!0===q)throw Error("Cannot call getHash after setting HMAC key");n=C(b);switch(c){case "HEX":d=function(c){return D(c,n)};break;case "B64":d=function(c){return E(c,n)};break;case "BYTES":d=F;break;default:throw Error("format must be HEX, B64, or BYTES");}l=r(e,g,a,h);for(f=1;f<v;f+=1)l=r(l,m,0,x(p));return d(l)};this.getHMAC=function(c,b){var d,f,l,k;if(!1===q)throw Error("Cannot call getHMAC without first setting HMAC key");
l=C(b);switch(c){case "HEX":d=function(c){return D(c,l)};break;case "B64":d=function(c){return E(c,l)};break;case "BYTES":d=F;break;default:throw Error("outputFormat must be HEX, B64, or BYTES");}f=r(e,g,a,h);k=u(t,x(p));k=r(f,m,n,k);return d(k)}}function b(b,c){this.a=b;this.b=c}function J(b,c,d){var a=b.length,e,g,f,h,l;c=c||[0];d=d||0;l=d>>>3;if(0!==a%2)throw Error("String of HEX type must be in byte increments");for(e=0;e<a;e+=2){g=parseInt(b.substr(e,2),16);if(isNaN(g))throw Error("String of HEX type contains invalid characters");
h=(e>>>1)+l;for(f=h>>>2;c.length<=f;)c.push(0);c[f]|=g<<8*(3-h%4)}return{value:c,binLen:4*a+d}}function K(b,c,d){var a=[],e,g,f,h,a=c||[0];d=d||0;g=d>>>3;for(e=0;e<b.length;e+=1)c=b.charCodeAt(e),h=e+g,f=h>>>2,a.length<=f&&a.push(0),a[f]|=c<<8*(3-h%4);return{value:a,binLen:8*b.length+d}}function L(b,c,d){var a=[],e=0,g,f,h,l,m,n,a=c||[0];d=d||0;c=d>>>3;if(-1===b.search(/^[a-zA-Z0-9=+\/]+$/))throw Error("Invalid character in base-64 string");f=b.indexOf("=");b=b.replace(/\=/g,"");if(-1!==f&&f<b.length)throw Error("Invalid '=' found in base-64 string");
for(f=0;f<b.length;f+=4){m=b.substr(f,4);for(h=l=0;h<m.length;h+=1)g="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(m[h]),l|=g<<18-6*h;for(h=0;h<m.length-1;h+=1){n=e+c;for(g=n>>>2;a.length<=g;)a.push(0);a[g]|=(l>>>16-8*h&255)<<8*(3-n%4);e+=1}}return{value:a,binLen:8*e+d}}function D(b,c){var d="",a=4*b.length,e,g;for(e=0;e<a;e+=1)g=b[e>>>2]>>>8*(3-e%4),d+="0123456789abcdef".charAt(g>>>4&15)+"0123456789abcdef".charAt(g&15);return c.outputUpper?d.toUpperCase():d}function E(b,
c){var d="",a=4*b.length,e,g,f;for(e=0;e<a;e+=3)for(f=e+1>>>2,g=b.length<=f?0:b[f],f=e+2>>>2,f=b.length<=f?0:b[f],f=(b[e>>>2]>>>8*(3-e%4)&255)<<16|(g>>>8*(3-(e+1)%4)&255)<<8|f>>>8*(3-(e+2)%4)&255,g=0;4>g;g+=1)8*e+6*g<=32*b.length?d+="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(f>>>6*(3-g)&63):d+=c.b64Pad;return d}function F(b){var c="",d=4*b.length,a,e;for(a=0;a<d;a+=1)e=b[a>>>2]>>>8*(3-a%4)&255,c+=String.fromCharCode(e);return c}function C(b){var c={outputUpper:!1,b64Pad:"="};
b=b||{};c.outputUpper=b.outputUpper||!1;!0===b.hasOwnProperty("b64Pad")&&(c.b64Pad=b.b64Pad);if("boolean"!==typeof c.outputUpper)throw Error("Invalid outputUpper formatting option");if("string"!==typeof c.b64Pad)throw Error("Invalid b64Pad formatting option");return c}function A(b,c){var d;switch(c){case "UTF8":case "UTF16BE":case "UTF16LE":break;default:throw Error("encoding must be UTF8, UTF16BE, or UTF16LE");}switch(b){case "HEX":d=J;break;case "TEXT":d=function(b,d,a){var p=[],h=[],l=0,m,n,k,
r,q,p=d||[0];d=a||0;k=d>>>3;if("UTF8"===c)for(m=0;m<b.length;m+=1)for(a=b.charCodeAt(m),h=[],128>a?h.push(a):2048>a?(h.push(192|a>>>6),h.push(128|a&63)):55296>a||57344<=a?h.push(224|a>>>12,128|a>>>6&63,128|a&63):(m+=1,a=65536+((a&1023)<<10|b.charCodeAt(m)&1023),h.push(240|a>>>18,128|a>>>12&63,128|a>>>6&63,128|a&63)),n=0;n<h.length;n+=1){q=l+k;for(r=q>>>2;p.length<=r;)p.push(0);p[r]|=h[n]<<8*(3-q%4);l+=1}else if("UTF16BE"===c||"UTF16LE"===c)for(m=0;m<b.length;m+=1){a=b.charCodeAt(m);"UTF16LE"===c&&
(n=a&255,a=n<<8|a>>>8);q=l+k;for(r=q>>>2;p.length<=r;)p.push(0);p[r]|=a<<8*(2-q%4);l+=2}return{value:p,binLen:8*l+d}};break;case "B64":d=L;break;case "BYTES":d=K;break;default:throw Error("format must be HEX, TEXT, B64, or BYTES");}return d}function k(a,c){var d=null,d=new b(a.a,a.b);return d=32>=c?new b(d.a>>>c|d.b<<32-c&4294967295,d.b>>>c|d.a<<32-c&4294967295):new b(d.b>>>c-32|d.a<<64-c&4294967295,d.a>>>c-32|d.b<<64-c&4294967295)}function G(a,c){var d=null;return d=32>=c?new b(a.a>>>c,a.b>>>c|a.a<<
32-c&4294967295):new b(0,a.a>>>c-32)}function M(a,c,d){return new b(a.a&c.a^~a.a&d.a,a.b&c.b^~a.b&d.b)}function N(a,c,d){return new b(a.a&c.a^a.a&d.a^c.a&d.a,a.b&c.b^a.b&d.b^c.b&d.b)}function O(a){var c=k(a,28),d=k(a,34);a=k(a,39);return new b(c.a^d.a^a.a,c.b^d.b^a.b)}function P(a){var c=k(a,14),d=k(a,18);a=k(a,41);return new b(c.a^d.a^a.a,c.b^d.b^a.b)}function Q(a){var c=k(a,1),d=k(a,8);a=G(a,7);return new b(c.a^d.a^a.a,c.b^d.b^a.b)}function R(a){var c=k(a,19),d=k(a,61);a=G(a,6);return new b(c.a^
d.a^a.a,c.b^d.b^a.b)}function S(a,c){var d,k,e;d=(a.b&65535)+(c.b&65535);k=(a.b>>>16)+(c.b>>>16)+(d>>>16);e=(k&65535)<<16|d&65535;d=(a.a&65535)+(c.a&65535)+(k>>>16);k=(a.a>>>16)+(c.a>>>16)+(d>>>16);return new b((k&65535)<<16|d&65535,e)}function T(a,c,d,k){var e,g,f;e=(a.b&65535)+(c.b&65535)+(d.b&65535)+(k.b&65535);g=(a.b>>>16)+(c.b>>>16)+(d.b>>>16)+(k.b>>>16)+(e>>>16);f=(g&65535)<<16|e&65535;e=(a.a&65535)+(c.a&65535)+(d.a&65535)+(k.a&65535)+(g>>>16);g=(a.a>>>16)+(c.a>>>16)+(d.a>>>16)+(k.a>>>16)+(e>>>
16);return new b((g&65535)<<16|e&65535,f)}function U(a,c,d,k,e){var g,f,h;g=(a.b&65535)+(c.b&65535)+(d.b&65535)+(k.b&65535)+(e.b&65535);f=(a.b>>>16)+(c.b>>>16)+(d.b>>>16)+(k.b>>>16)+(e.b>>>16)+(g>>>16);h=(f&65535)<<16|g&65535;g=(a.a&65535)+(c.a&65535)+(d.a&65535)+(k.a&65535)+(e.a&65535)+(f>>>16);f=(a.a>>>16)+(c.a>>>16)+(d.a>>>16)+(k.a>>>16)+(e.a>>>16)+(g>>>16);return new b((f&65535)<<16|g&65535,h)}function x(a){var c,d;c=[3238371032,914150663,812702999,4144912697,4290775857,1750603025,1694076839,
3204075428];d=[1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225];switch(a){case "SHA-224":a=c;break;case "SHA-256":a=d;break;case "SHA-384":a=[new b(3418070365,c[0]),new b(1654270250,c[1]),new b(2438529370,c[2]),new b(355462360,c[3]),new b(1731405415,c[4]),new b(41048885895,c[5]),new b(3675008525,c[6]),new b(1203062813,c[7])];break;case "SHA-512":a=[new b(d[0],4089235720),new b(d[1],2227873595),new b(d[2],4271175723),new b(d[3],1595750129),new b(d[4],2917565137),
new b(d[5],725511199),new b(d[6],4215389547),new b(d[7],327033209)];break;default:throw Error("Unknown SHA variant");}return a}function B(a,c,d){var k,e,g,f,h,l,m,n,u,r,q,w,t,v,z,x,A,B,C,D,E,F,y=[],G;c=c.slice();if("SHA-384"===d||"SHA-512"===d)r=80,w=2,F=b,t=S,v=T,z=U,x=Q,A=R,B=O,C=P,E=N,D=M,G=H;else throw Error("Unexpected error in SHA-2 implementation");d=c[0];k=c[1];e=c[2];g=c[3];f=c[4];h=c[5];l=c[6];m=c[7];for(q=0;q<r;q+=1)16>q?(u=q*w,n=a.length<=u?0:a[u],u=a.length<=u+1?0:a[u+1],y[q]=new F(n,
u)):y[q]=v(A(y[q-2]),y[q-7],x(y[q-15]),y[q-16]),n=z(m,C(f),D(f,h,l),G[q],y[q]),u=t(B(d),E(d,k,e)),m=l,l=h,h=f,f=t(g,n),g=e,e=k,k=d,d=t(n,u);c[0]=t(d,c[0]);c[1]=t(k,c[1]);c[2]=t(e,c[2]);c[3]=t(g,c[3]);c[4]=t(f,c[4]);c[5]=t(h,c[5]);c[6]=t(l,c[6]);c[7]=t(m,c[7]);return c}var a,H;a=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,
1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298];H=[new b(a[0],3609767458),new b(a[1],
602891725),new b(a[2],3964484399),new b(a[3],2173295548),new b(a[4],4081628472),new b(a[5],3053834265),new b(a[6],2937671579),new b(a[7],3664609560),new b(a[8],2734883394),new b(a[9],1164996542),new b(a[10],1323610764),new b(a[11],3590304994),new b(a[12],4068182383),new b(a[13],991336113),new b(a[14],633803317),new b(a[15],3479774868),new b(a[16],2666613458),new b(a[17],944711139),new b(a[18],2341262773),new b(a[19],2007800933),new b(a[20],1495990901),new b(a[21],1856431235),new b(a[22],3175218132),
new b(a[23],2198950837),new b(a[24],3999719339),new b(a[25],766784016),new b(a[26],2566594879),new b(a[27],3203337956),new b(a[28],1034457026),new b(a[29],2466948901),new b(a[30],3758326383),new b(a[31],168717936),new b(a[32],1188179964),new b(a[33],1546045734),new b(a[34],1522805485),new b(a[35],2643833823),new b(a[36],2343527390),new b(a[37],1014477480),new b(a[38],1206759142),new b(a[39],344077627),new b(a[40],1290863460),new b(a[41],3158454273),new b(a[42],3505952657),new b(a[43],106217008),new b(a[44],
3606008344),new b(a[45],1432725776),new b(a[46],1467031594),new b(a[47],851169720),new b(a[48],3100823752),new b(a[49],1363258195),new b(a[50],3750685593),new b(a[51],3785050280),new b(a[52],3318307427),new b(a[53],3812723403),new b(a[54],2003034995),new b(a[55],3602036899),new b(a[56],1575990012),new b(a[57],1125592928),new b(a[58],2716904306),new b(a[59],442776044),new b(a[60],593698344),new b(a[61],3733110249),new b(a[62],2999351573),new b(a[63],3815920427),new b(3391569614,3928383900),new b(3515267271,
566280711),new b(3940187606,3454069534),new b(4118630271,4000239992),new b(116418474,1914138554),new b(174292421,2731055270),new b(289380356,3203993006),new b(460393269,320620315),new b(685471733,587496836),new b(852142971,1086792851),new b(1017036298,365543100),new b(1126000580,2618297676),new b(1288033470,3409855158),new b(1501505948,4234509866),new b(1607167915,987167468),new b(1816402316,1246189591)];"function"===typeof define&&define.amd?define(function(){return w}):"undefined"!==typeof exports?
"undefined"!==typeof module&&module.exports?module.exports=exports=w:exports=w:I.jsSHA=w})(this);
