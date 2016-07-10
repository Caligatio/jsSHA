/* Kind of hack to get the tests working both in the browser and node.js */
if (("undefined" !== typeof module) && module["exports"])
{
	mocha = require("mocha");
	chai = require("chai");
	jsSHA = require("../src/sha_dev.js");
}

String.prototype.repeat = function(times) {
    return (new Array(times + 1)).join(this);
}

/* These are used often so make a global copy that everything can reference */
var millionaAscii = "a".repeat(1000000), millionaHex = "61".repeat(1000000), millionaB64 = "YWFh".repeat(333333) + "YQ==";

/* ============================================================================
 *                             Begin HMAC Tests
 * ============================================================================
 */
var hmacTests = [
	{
		"hash": "SHA-1",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen<blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbjxibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F10111213"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhM="}
				],
				"outputs": [
					{"type": "HEX", "value": "4c99ff0cb1b31bd33f8431dbaf4d17fcd356a807"},
					{"type": "B64", "value": "TJn/DLGzG9M/hDHbr00X/NNWqAc="}
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen=blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbj1ibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw=="}
				],
				"outputs": [
					{ "type": "HEX", "value": "5fd596ee78d5553c8ff4e72d266dfd192366da29"},
					{"type": "B64", "value": "X9WW7njVVTyP9OctJm39GSNm2ik="}
				]
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen=blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbj1ibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiYw=="}
				],
				"outputs": [
					{"type": "HEX", "value": "2d51b2f7750e410584662e38f133435f4c4fd42a"},
					{"type": "B64", "value": "LVGy93UOQQWEZi448TNDX0xP1Co="}
				]
			}
		]
	},
	{
		"hash": "SHA-224",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen<blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbjxibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGw=="}
				],
				"outputs": [
					{"type": "HEX", "value": "e3d249a8cfb67ef8b7a169e9a0a599714a2cecba65999a51beb8fbbe"},
					{"type": "B64", "value": "49JJqM+2fvi3oWnpoKWZcUos7LplmZpRvrj7vg=="}
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen=blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbj1ibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw=="}
				],
				"outputs": [
					{"type": "HEX", "value": "c7405e3ae058e8cd30b08b4140248581ed174cb34e1224bcc1efc81b"},
					{"type": "B64", "value": "x0BeOuBY6M0wsItBQCSFge0XTLNOEiS8we/IGw=="}
				]
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen=blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbj1ibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiYw=="}
				],
				"outputs": [
					{"type": "HEX", "value": "91c52509e5af8531601ae6230099d90bef88aaefb961f4080abc014d"},
					{"type": "B64", "value": "kcUlCeWvhTFgGuYjAJnZC++Iqu+5YfQICrwBTQ=="}
				],
			}
		]
	},
	{
		"hash": "SHA3-224",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen<blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbjxibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGw=="}
				],
				"outputs": [
					{"type": "HEX", "value": "332cfd59347fdb8e576e77260be4aba2d6dc53117b3bfb52c6d18c04"},
					{"type": "B64", "value": "Myz9WTR/245XbncmC+SrotbcUxF7O/tSxtGMBA=="}
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen=blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbj1ibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P"}
				],
				"outputs": [
					{"type": "HEX", "value": "d8b733bcf66c644a12323d564e24dcf3fc75f231f3b67968359100c7"},
					{"type": "B64", "value": "2LczvPZsZEoSMj1WTiTc8/x18jHztnloNZEAxw=="}
				]
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen>blocklen"},
					{"type": "HEX", "value": "53616d706c65206d65737361676520666f72206b65796c656e3e626c6f636b6c656e"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbj5ibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaab"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqqw=="}
				],
				"outputs": [
					{"type": "HEX", "value": "078695eecc227c636ad31d063a15dd05a7e819a66ec6d8de1e193e59"},
					{"type": "B64", "value": "B4aV7swifGNq0x0GOhXdBafoGaZuxtjeHhk+WQ=="}
				],
			}
		]
	},
	{
		"hash": "SHA-256",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen<blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbjxibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}
				],

				"outputs": [
					{"type": "HEX", "value": "a28cf43130ee696a98f14a37678b56bcfcbdd9e5cf69717fecf5480f0ebdf790"},
					{"type": "B64", "value": "ooz0MTDuaWqY8Uo3Z4tWvPy92eXPaXF/7PVIDw6995A="}
				],
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen=blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbj1ibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw=="}
				],
				"outputs": [
					{"type": "HEX", "value": "8bb9a1db9806f20df7f77b82138c7914d174d59e13dc4d0169c9057b133e1d62"},
					{"type": "B64", "value": "i7mh25gG8g3393uCE4x5FNF01Z4T3E0BackFexM+HWI="}
				],
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen=blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbj1ibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiYw=="}
				],
				"outputs": [
					{"type": "HEX", "value": "bdccb6c72ddeadb500ae768386cb38cc41c63dbb0878ddb9c7a38a431b78378d"},
					{"type": "B64", "value": "vcy2xy3erbUArnaDhss4zEHGPbsIeN25x6OKQxt4N40="}
				]
			}
		]
	},
	{
		"hash": "SHA3-256",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen<blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbjxibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}
				],

				"outputs": [
					{"type": "HEX", "value": "4fe8e202c4f058e8dddc23d8c34e467343e23555e24fc2f025d598f558f67205"},
					{"type": "B64", "value": "T+jiAsTwWOjd3CPYw05Gc0PiNVXiT8LwJdWY9Vj2cgU="}
				],
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen=blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbj1ibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384858687"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGhw=="}
				],
				"outputs": [
					{"type": "HEX", "value": "68b94e2e538a9be4103bebb5aa016d47961d4d1aa906061313b557f8af2c3faa"},
					{"type": "B64", "value": "aLlOLlOKm+QQO+u1qgFtR5YdTRqpBgYTE7VX+K8sP6o="}
				],
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen>blocklen"},
					{"type": "HEX", "value": "53616d706c65206d65737361676520666f72206b65796c656e3e626c6f636b6c656e"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbj5ibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaan"}
				],
				"outputs": [
					{"type": "HEX", "value": "9bcf2c238e235c3ce88404e813bd2f3a97185ac6f238c63d6229a00b07974258"},
					{"type": "B64", "value": "m88sI44jXDzohAToE70vOpcYWsbyOMY9YimgCweXQlg="}
				]
			}
		]
	},
	{
		"hash": "SHA-384",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen<blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbjxibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v"}
				],
				"outputs": [
					{"type": "HEX", "value": "6eb242bdbb582ca17bebfa481b1e23211464d2b7f8c20b9ff2201637b93646af5ae9ac316e98db45d9cae773675eeed0"},
					{"type": "B64", "value": "brJCvbtYLKF76/pIGx4jIRRk0rf4wguf8iAWN7k2Rq9a6awxbpjbRdnK53NnXu7Q"}
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen=blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbj1ibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8="}
				],
				"outputs": [
					{"type": "HEX", "value": "63c5daa5e651847ca897c95814ab830bededc7d25e83eef9195cd45857a37f448947858f5af50cc2b1b730ddf29671a9"},
					{"type": "B64", "value": "Y8XapeZRhHyol8lYFKuDC+3tx9Jeg+75GVzUWFejf0SJR4WPWvUMwrG3MN3ylnGp"}
				]
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen=blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbj1ibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsc="}
				],
				"outputs": [
					{"type": "HEX", "value": "5b664436df69b0ca22551231a3f0a3d5b4f97991713cfa84bff4d0792eff96c27dccbbb6f79b65d548b40e8564cef594"},
					{"type": "B64", "value": "W2ZENt9psMoiVRIxo/Cj1bT5eZFxPPqEv/TQeS7/lsJ9zLu295tl1Ui0DoVkzvWU"}
				]
			}
		]
	},
	{
		"hash": "SHA3-384",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen<blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbjxibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v"}
				],
				"outputs": [
					{"type": "HEX", "value": "d588a3c51f3f2d906e8298c1199aa8ff6296218127f6b38a90b6afe2c5617725bc99987f79b22a557b6520db710b7f42"},
					{"type": "B64", "value": "1YijxR8/LZBugpjBGZqo/2KWIYEn9rOKkLav4sVhdyW8mZh/ebIqVXtlINtxC39C"}
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen=blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbj1ibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F6061626364656667"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmc="}
				],
				"outputs": [
					{"type": "HEX", "value": "a27d24b592e8c8cbf6d4ce6fc5bf62d8fc98bf2d486640d9eb8099e24047837f5f3bffbe92dcce90b4ed5b1e7e44fa90"},
					{"type": "B64", "value": "on0ktZLoyMv21M5vxb9i2PyYvy1IZkDZ64CZ4kBHg39fO/++ktzOkLTtWx5+RPqQ"}
				]
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen>blocklen"},
					{"type": "HEX", "value": "53616d706c65206d65737361676520666f72206b65796c656e3e626c6f636b6c656e"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbj5ibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F9091929394959697"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpc="}
				],
				"outputs": [
					{"type": "HEX", "value": "e5ae4c739f455279368ebf36d4f5354c95aa184c899d3870e460ebc288ef1f9470053f73f7c6da2a71bcaec38ce7d6ac"},
					{"type": "B64", "value": "5a5Mc59FUnk2jr821PU1TJWqGEyJnThw5GDrwojvH5RwBT9z98baKnG8rsOM59as"}
				]
			}
		]
	},
	{
		"hash": "SHA-512",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen<blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbjxibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw=="}
				],
				"outputs": [
					{"type": "HEX", "value": "fd44c18bda0bb0a6ce0e82b031bf2818f6539bd56ec00bdc10a8a2d730b3634de2545d639b0f2cf710d0692c72a1896f1f211c2b922d1a96c392e07e7ea9fedc"},
					{"type": "B64", "value": "/UTBi9oLsKbODoKwMb8oGPZTm9VuwAvcEKii1zCzY03iVF1jmw8s9xDQaSxyoYlvHyEcK5ItGpbDkuB+fqn+3A=="}
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen=blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbj1ibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8="}
				],
				"outputs": [
					{"type": "HEX", "value": "fc25e240658ca785b7a811a8d3f7b4ca48cfa26a8a366bf2cd1f836b05fcb024bd36853081811d6cea4216ebad79da1cfcb95ea4586b8a0ce356596a55fb1347"},
					{"type": "B64", "value": "/CXiQGWMp4W3qBGo0/e0ykjPomqKNmvyzR+DawX8sCS9NoUwgYEdbOpCFuutedoc/LlepFhrigzjVllqVfsTRw=="}
				],
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen=blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbj1ibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsc="}
				],
				"outputs": [
					{"type": "HEX", "value": "d93ec8d2de1ad2a9957cb9b83f14e76ad6b5e0cce285079a127d3b14bccb7aa7286d4ac0d4ce64215f2bc9e6870b33d97438be4aaa20cda5c5a912b48b8e27f3"},
					{"type": "B64", "value": "2T7I0t4a0qmVfLm4PxTnata14MzihQeaEn07FLzLeqcobUrA1M5kIV8ryeaHCzPZdDi+SqogzaXFqRK0i44n8w=="}
				]
			}
		]
	},
	{
		"hash": "SHA3-512",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen<blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbjxibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw=="}
				],
				"outputs": [
					{"type": "HEX", "value": "4efd629d6c71bf86162658f29943b1c308ce27cdfa6db0d9c3ce81763f9cbce5f7ebe9868031db1a8f8eb7b6b95e5c5e3f657a8996c86a2f6527e307f0213196"},
					{"type": "B64", "value": "Tv1inWxxv4YWJljymUOxwwjOJ836bbDZw86Bdj+cvOX36+mGgDHbGo+Ot7a5XlxeP2V6iZbIai9lJ+MH8CExlg=="}
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen=blocklen"},
					{"type": "HEX", "value": "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbj1ibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F4041424344454647"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZH"}
				],
				"outputs": [
					{"type": "HEX", "value": "544e257ea2a3e5ea19a590e6a24b724ce6327757723fe2751b75bf007d80f6b360744bf1b7a88ea585f9765b47911976d3191cf83c039f5ffab0d29cc9d9b6da"},
					{"type": "B64", "value": "VE4lfqKj5eoZpZDmoktyTOYyd1dyP+J1G3W/AH2A9rNgdEvxt6iOpYX5dltHkRl20xkc+DwDn1/6sNKcydm22g=="}
				],
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": "Sample message for keylen>blocklen"},
					{"type": "HEX", "value": "53616d706c65206d65737361676520666f72206b65796c656e3e626c6f636b6c656e"},
					{"type": "B64", "value": "U2FtcGxlIG1lc3NhZ2UgZm9yIGtleWxlbj5ibG9ja2xlbg=="}
				],
				"keyInputs": [
					{"type": "HEX", "value": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F8081828384858687"},
					{"type": "B64", "value": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGhw=="}
				],
				"outputs": [
					{"type": "HEX", "value": "5f464f5e5b7848e3885e49b2c385f0694985d0e38966242dc4a5fe3fea4b37d46b65ceced5dcf59438dd840bab22269f0ba7febdb9fcf74602a35666b2a32915"},
					{"type": "B64", "value": "X0ZPXlt4SOOIXkmyw4XwaUmF0OOJZiQtxKX+P+pLN9RrZc7O1dz1lDjdhAurIiafC6f+vbn890YCo1ZmsqMpFQ=="}
				]
			}
		]
	}
]

hmacTests.forEach(function(testSuite) {
	describe("HMAC " + testSuite["hash"] + " Tests", function() {
		try
		{
			testSuite["tests"].forEach(function(test) {
				test["ptInputs"].forEach(function(ptInput) {
					test["keyInputs"].forEach(function(keyInput) {
						var hash = new jsSHA(testSuite["hash"], ptInput["type"]);
						hash.setHMACKey(keyInput["value"], keyInput["type"])
						hash.update(ptInput["value"]);
						test["outputs"].forEach(function(output) {
							it(ptInput["type"] + " Input - " + test["name"] + " " + keyInput["type"] + " Key  - " + output["type"] + " Output", function() {
								chai.assert.equal(hash.getHMAC(output["type"]), output["value"]);
							});
						});
					});
				});
			});
		}
		catch(e)
		{
			if (e.message != "Chosen SHA variant is not supported")
			{
				throw new Error("Testing of HMAC " + testSuite["hash"] + " failed");
			}
		}
	});
});
/* ============================================================================
 *                              End HMAC Tests
 * ============================================================================
 */
