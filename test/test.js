/* Kind of hack to get the tests working both in the browser and node.js */
if (("undefined" !== typeof module) && module["exports"])
{
	mocha = require("mocha");
	chai = require("chai");
	jsSHA = require("../src/sha.js");
}

/* These are used often so make a global copy that everything can reference */
var millionaAscii = "a".repeat(1000000), millionaHex = "61".repeat(1000000), millionaB64 = "YWFh".repeat(333333) + "YQ==";

/* ============================================================================
 *                            Begin Basic Hash Tests
 * ============================================================================
 */
var hashTests = [
	{
		"hash": "SHA-1",
		"tests" : [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "abc"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"},
				],
				"outputs" : [
					{"type": "HEX", "value": "a9993e364706816aba3e25717850c26c9cd0d89d"},
					{"type": "B64", "value": "qZk+NkcGgWq6PiVxeFDCbJzQ2J0="},
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
					{"type": "HEX", "value": "6162636462636465636465666465666765666768666768696768696A68696A6B696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071"},
					{"type": "B64", "value": "YWJjZGJjZGVjZGVmZGVmZ2VmZ2hmZ2hpZ2hpamhpamtpamtsamtsbWtsbW5sbW5vbW5vcG5vcHE="},
				],
				"outputs" : [
					{"type": "HEX", "value": "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
					{"type": "B64", "value": "hJg+RBw70m66rkqh+VEp5eVGcPE="},
				]
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii},
					{"type": "HEX", "value": millionaHex},
					{"type": "B64", "value": millionaB64},
				],
				"outputs" : [
					{"type": "HEX", "value": "34aa973cd4c4daa4f61eeb2bdbad27316534016f"},
					{"type": "B64", "value": "NKqXPNTE2qT2Husr260nMWU0AW8="},
				]
			}
		],
	},
	{
		"hash": "SHA-224",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "abc"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"},
				],
				"outputs" : [
					{"type": "HEX", "value": "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"},
					{"type": "B64", "value": "Iwl9IjQF2CKGQqR3vaJVsyqtvOS9oLP342ydpw=="},
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
					{"type": "HEX", "value": "6162636462636465636465666465666765666768666768696768696A68696A6B696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071"},
					{"type": "B64", "value": "YWJjZGJjZGVjZGVmZGVmZ2VmZ2hmZ2hpZ2hpamhpamtpamtsamtsbWtsbW5sbW5vbW5vcG5vcHE="},
				],
				"outputs" : [
					{"type": "HEX", "value": "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"},
					{"type": "B64", "value": "dTiLFlEndsxdul2h/YkBULDGRVy09YsZUlIlJQ=="},
				]
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii},
					{"type": "HEX", "value": millionaHex},
					{"type": "B64", "value": millionaB64},
				],
				"outputs" : [
					{"type": "HEX", "value": "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"},
					{"type": "B64", "value": "IHlGVZgMkdi7tMHql2GKS/A/QlgZSLLuTuetZw=="},
				]
			}
		]
	},
	{
		"hash": "SHA-256",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "abc"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"},
				],
				"outputs" : [
					{"type": "HEX", "value": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
					{"type": "B64", "value": "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="},
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
					{"type": "HEX", "value": "6162636462636465636465666465666765666768666768696768696A68696A6B696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071"},
					{"type": "B64", "value": "YWJjZGJjZGVjZGVmZGVmZ2VmZ2hmZ2hpZ2hpamhpamtpamtsamtsbWtsbW5sbW5vbW5vcG5vcHE="},
				],
				"outputs" : [
					{"type": "HEX", "value": "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
					{"type": "B64", "value": "JI1qYdIGOLjlwCaTDD5gOaM85Flk/yFn9uzt1BnbBsE="},
				]
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii},
					{"type": "HEX", "value": millionaHex},
					{"type": "B64", "value": millionaB64},
				],
				"outputs" : [
					{"type": "HEX", "value": "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"},
					{"type": "B64", "value": "zcduXJkU+5KBocfihNc+Z/GAmkiklyAOBG05zMcRLNA="},
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
					{"type": "TEXT", "value": "abc"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"},
				],
				"outputs" : [
					{"type": "HEX", "value": "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
					{"type": "B64", "value": "ywB1P0WjXou1oD1pmsZQBycsMqsO3tFjGotgWkP/W+2AhgcroefMI1i67KE0yCWn"},
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"},
					{"type": "HEX", "value": "61626364656667686263646566676869636465666768696A6465666768696A6B65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E6F696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F707172736D6E6F70717273746E6F707172737475"},
					{"type": "B64", "value": "YWJjZGVmZ2hiY2RlZmdoaWNkZWZnaGlqZGVmZ2hpamtlZmdoaWprbGZnaGlqa2xtZ2hpamtsbW5oaWprbG1ub2lqa2xtbm9wamtsbW5vcHFrbG1ub3Bxcmxtbm9wcXJzbW5vcHFyc3Rub3BxcnN0dQ=="},
				],
				"outputs" : [
					{"type": "HEX", "value": "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"},
					{"type": "B64", "value": "CTMMM/cRR+g9GS/Hgs0bR1MRGxc7OwXSL6CAhuOw9xL8x8caVX4tuWbD6fqRdGA5"},
				]
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii},
					{"type": "HEX", "value": millionaHex},
					{"type": "B64", "value": millionaB64},
				],
				"outputs" : [
					{"type": "HEX", "value": "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"},
					{"type": "B64", "value": "nQ4YCXFkdMsIboNOMQpKHO0UnpwA8khSeXLOxXBMKlsHuLPcOOzE666X3dh/PYmF"},
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
					{"type": "TEXT", "value": "abc"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"},
				],
				"outputs" : [
					{"type": "HEX", "value": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
					{"type": "B64", "value": "3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw=="},
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"},
					{"type": "HEX", "value": "61626364656667686263646566676869636465666768696A6465666768696A6B65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E6F696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F707172736D6E6F70717273746E6F707172737475"},
					{"type": "B64", "value": "YWJjZGVmZ2hiY2RlZmdoaWNkZWZnaGlqZGVmZ2hpamtlZmdoaWprbGZnaGlqa2xtZ2hpamtsbW5oaWprbG1ub2lqa2xtbm9wamtsbW5vcHFrbG1ub3Bxcmxtbm9wcXJzbW5vcHFyc3Rub3BxcnN0dQ=="},
				],
				"outputs" : [
					{"type": "HEX", "value": "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"},
					{"type": "B64", "value": "jpWbddrjE9qM9PcoFPwUP493ecbrn3+hcpmurbaIkBhQHSieSQD35DMbmd7EtUM6x9Mp7rbdJlReluVbh0vpCQ=="},
				]
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii},
					{"type": "HEX", "value": millionaHex},
					{"type": "B64", "value": millionaB64},
				],
				"outputs" : [
					{"type": "HEX", "value": "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"},
					{"type": "B64", "value": "5xhIPQznaWROLkLHvBW0Y44fmLE7IEQoVjKoA6+pc+veD/JEh36mCkywQyzld8Mb6wCcXCxJqi5OrbIXrYzAmw=="},
				]
			}
		]
	}
]

hashTests.forEach(function(testSuite) {
	describe("Basic " + testSuite["hash"] + " Tests", function() {
		try
		{
			testSuite["tests"].forEach(function(test) {
				test["ptInputs"].forEach(function(ptInput) {
					test["outputs"].forEach(function(output) {
						var hash = new jsSHA(testSuite["hash"], ptInput["type"]);
						hash.update(ptInput["value"]);
						it(test["name"] + " " + ptInput["type"] + " Input - " + output["type"] + " Output", function() {
							chai.assert.equal(hash.getHash(output["type"]), output["value"]);
						});
					});
				});
			});
		}
		catch(e)
		{
			if (e.message != "Chosen SHA variant is not supported")
			{
				throw new Error("Testing of " + testSuite["hash"] + " failed");
			}
		}
	});
});
/* ============================================================================
 *                           End Basic Hash Tests
 * ============================================================================
 */

/* ============================================================================
 *                        Begin Multi-Round Hash Tests
 * ============================================================================
 */
var multiRoundTests = [
	{
		"hash": "SHA-1",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "abc"}
				],
				"outputs": [
					{"type": "HEX", "rounds": 5, "value": "b5c64925eb9940259be55c005c9cecc7d9897ef9"},
					{"type": "HEX", "rounds": 10, "value": "94ebc0d3c81b61eb98670666f5fde68560c4e165"}
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
					{"type": "TEXT", "value": "abc"}
				],
				"outputs": [
					{"type": "HEX", "rounds": 5, "value": "5b4b17f720d52c6a864229e784fb636184ca48ce7dd848fdad986239"},
					{"type": "HEX", "rounds": 10, "value": "5230eb37afcc115f4f380a9f50c4743d457bbe586e6faa6bf21696f9"}
				]
			}
		]
	},
	{
		"hash": "SHA-256",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "abc"}
				],
				"outputs": [
					{"type": "HEX", "rounds": 5, "value": "184f6d6e82554c051b33f15e7ffffecb0cc0f461a29096c41c214e168e34c21d"},
					{"type": "HEX", "rounds": 10, "value": "10e286f907c0fe9f02cea3864cbaec04ae47e2c0a13b60473bc9968a4851b219"}
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
					{"type": "TEXT", "value": "abc"}
				],
				"outputs": [
					{"type": "HEX", "rounds": 5, "value": "a4aa4cd8534aecb2d07765f928303d1d2609835ea85d14312bcee264e99dc5d7dc08bb18ec694053fd7fe6906706d55f"},
					{"type": "HEX", "rounds": 10, "value": "b80c82979453f2f3dcf89ec4cef5c71e89837537de170e3942af8b37757cc790d4cc4ebe16a52164ad19f3a02d192f1c"}
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
					{"type": "TEXT", "value": "abc"}
				],
				"outputs": [
					{"type": "HEX", "rounds": 5, "value": "299b2e3ce932e4d0e9005345e37af5a4cc6be21e6b6e21231ce71ccde2a7aba4a6822cd7a9aaf9b13918db05ede70d3f1e6af65f8ad0bda1c4c4fa263e3cabdd"},
					{"type": "HEX", "rounds": 10, "value": "4c3ead8c83442fff47d4386702044f2a6c19730a806de541964b0fa9987cac08641611e02b2e0742ef2600ff82bfe3a711567c8e76dda16b4948f4c76e3c6e9c"}
				]
			}
		]
	}
]

multiRoundTests.forEach(function(testSuite) {
	describe("Multiround " + testSuite["hash"] + " Tests", function() {
		try
		{
			testSuite["tests"].forEach(function(test) {
				test["ptInputs"].forEach(function(ptInput) {
					test["outputs"].forEach(function(output) {
						var hash = new jsSHA(testSuite["hash"], ptInput["type"], {"numRounds": output["rounds"]});
						hash.update(ptInput["value"]);
						it(test["name"] + " " + ptInput["type"] + " Input - " + output["type"] + " Output - " + output["rounds"] + " Rounds ", function() {
							chai.assert.equal(hash.getHash(output["type"]), output["value"]);
						});
					});
				});
			});
		}
		catch(e)
		{
			if (e.message != "Chosen SHA variant is not supported")
			{
				throw new Error("Testing of multi-round " + testSuite["hash"] + " failed");
			}
		}
	});
});
/* ============================================================================
 *                        End Multi-Round Hash Tests
 * ============================================================================
 */

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
