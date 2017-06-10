/* Kind of hack to get the tests working both in the browser and node.js */

/*jslint
	bitwise: true, multivar: true, for: true, this: true, sub: true, esversion: 3
*/
if (("undefined" !== typeof module) && module["exports"])
{
	mocha = require("mocha");
	chai = require("chai");
	jsSHA = require("../src/sha_dev.js");
}

String.prototype.repeat = function(times) {
	return (new Array(times + 1)).join(this);
};

function hexToArrayBuffer(hexStr)
{
	var arrayBuffer = new ArrayBuffer(hexStr.length / 2), arrView = new Uint8Array(arrayBuffer), i;

	for (i = 0; i < hexStr.length; i += 2)
	{
		num = parseInt(hexStr.substr(i, 2), 16);
		if (!isNaN(num))
		{
			arrView[i >>> 1] = num;
		  }
		else
		{
			throw new Error("String of HEX type contains invalid characters");
		}
	}

	return arrayBuffer;
}

function arrayBufferToHex(arrayBuffer)
{
	var hex_tab = "0123456789abcdef", arrView = new Uint8Array(arrayBuffer), i, str = "";

	for (i = 0; i < arrView.length; i += 1)
	{
		str += (hex_tab.charAt((arrView[i] >>> 4) & 0xF) +
			hex_tab.charAt(arrView[i] & 0xF));
	}

	return str;
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
					{"type": "TEXT", "value": "abc", "encoding": "UTF8"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"}
				],
				"outputs" : [
					{"type": "HEX", "value": "a9993e364706816aba3e25717850c26c9cd0d89d"},
					{"type": "B64", "value": "qZk+NkcGgWq6PiVxeFDCbJzQ2J0="}
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "encoding": "UTF8"},
					{"type": "HEX", "value": "6162636462636465636465666465666765666768666768696768696A68696A6B696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071"},
					{"type": "B64", "value": "YWJjZGJjZGVjZGVmZGVmZ2VmZ2hmZ2hpZ2hpamhpamtpamtsamtsbWtsbW5sbW5vbW5vcG5vcHE="}
				],
				"outputs" : [
					{"type": "HEX", "value": "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
					{"type": "B64", "value": "hJg+RBw70m66rkqh+VEp5eVGcPE="}
				]
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF8"},
					{"type": "HEX", "value": millionaHex},
					{"type": "B64", "value": millionaB64}
				],
				"outputs" : [
					{"type": "HEX", "value": "34aa973cd4c4daa4f61eeb2bdbad27316534016f"},
					{"type": "B64", "value": "NKqXPNTE2qT2Husr260nMWU0AW8="}
				]
			},
			{
				"name": "Short UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "af68535cb6d1af8b6e3c60305cf0bfae6c57de36"}
				]
			},
			{
				"name": "Medium UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "bef8f6cd143d7fa6d9f726eef2ff444391fe76ac"}
				]
			},
			{
				"name": "Long UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "94359e86fb2a95ceed60bd0b58bcffd7192d9c16"}
				]
			},
			{
				"name": "Short UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "9f04f41a848514162050e3d68c1a7abb441dc2b5"}
				]
			},
			{
				"name": "Medium UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "51d7d8769ac72c409c5b0e3f69c60adc9a039014"}
				]
			},
			{
				"name": "Long UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "c4609560a108a0c626aa7f2b38a65566739353c5"}
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
					{"type": "TEXT", "value": "abc", "encoding": "UTF8"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"}
				],
				"outputs" : [
					{"type": "HEX", "value": "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"},
					{"type": "B64", "value": "Iwl9IjQF2CKGQqR3vaJVsyqtvOS9oLP342ydpw=="}
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "encoding": "UTF8"},
					{"type": "HEX", "value": "6162636462636465636465666465666765666768666768696768696A68696A6B696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071"},
					{"type": "B64", "value": "YWJjZGJjZGVjZGVmZGVmZ2VmZ2hmZ2hpZ2hpamhpamtpamtsamtsbWtsbW5sbW5vbW5vcG5vcHE="}
				],
				"outputs" : [
					{"type": "HEX", "value": "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"},
					{"type": "B64", "value": "dTiLFlEndsxdul2h/YkBULDGRVy09YsZUlIlJQ=="}
				]
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF8"},
					{"type": "HEX", "value": millionaHex},
					{"type": "B64", "value": millionaB64}
				],
				"outputs" : [
					{"type": "HEX", "value": "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"},
					{"type": "B64", "value": "IHlGVZgMkdi7tMHql2GKS/A/QlgZSLLuTuetZw=="}
				]
			},
			{
				"name": "Short UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "4751f7e6ffd48fd96549183745ed3b51517cf79479475670299dcaa1"}
				]
			},
			{
				"name": "Medium UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "1591f5aa2b329fa3cd3645ca52e62cb859fee74922e4495783e17213"}
				]
			},
			{
				"name": "Long UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "3bd39fdaa867ff89948d8699c179b79ece1eb8a78d2413481824397a"}
				]
			},
			{
				"name": "Short UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "57ba76af9d4846f1e08697d79422ea3f516fe3145ad7fc4c93ba85ac"}
				]
			},
			{
				"name": "Medium UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "2d30dab9655cd28a84790ae02e742d28b02c1d5d2e7196cee1732ca5"}
				]
			},
			{
				"name": "Long UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "11bb18d73d725c7d104e1ca15ee9b5094c3703ac152ffb2484b45a78"}
				]
			}
		]
	},
	{
		"hash": "SHA3-224",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF8"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"}
				],
				"outputs" : [
					{"type": "HEX", "value": "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"},
					{"type": "B64", "value": "5kKCTD+M8krQkjTufTx2b8mjpRaNDJStc7Rv3w=="}
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "encoding": "UTF8"},
					{"type": "HEX", "value": "6162636462636465636465666465666765666768666768696768696A68696A6B696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071"},
					{"type": "B64", "value": "YWJjZGJjZGVjZGVmZGVmZ2VmZ2hmZ2hpZ2hpamhpamtpamtsamtsbWtsbW5sbW5vbW5vcG5vcHE="}
				],
				"outputs" : [
					{"type": "HEX", "value": "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33"},
					{"type": "B64", "value": "iiQQixVK2iHJ/VV0SUR5ulx+erdu8mTq0PzOMw=="}
				]
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF8"},
					{"type": "HEX", "value": millionaHex},
					{"type": "B64", "value": millionaB64}
				],
				"outputs" : [
					{"type": "HEX", "value": "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c"},
					{"type": "B64", "value": "1pM1uTMlGS5RapEubRmhXLUcbtXBUkPnp/1lPA=="}
				]
			},
			{
				"name": "Short UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "d5c49292551814f4dd267d4b9f3e10bc12d97ae01a75688fc94973c6"}
				]
			},
			{
				"name": "Medium UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "e8d8ae12828497d89f36e573ab18f6237028e063f0bc1e8dce812a54"}
				]
			},
			{
				"name": "Long UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "ea9658eb20be9aaeb24ced54c9e9688dd127d249e92b3e3e9b47bbe8"}
				]
			},
			{
				"name": "Short UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "bcaf706ac4a322d3b95f7fcd33e623a82b83ffa5b4044df21fb970de"}
				]
			},
			{
				"name": "Medium UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "5e3d1dc2dc50b3d3bf03beac724d6d3203231eea900449fd4f542540"}
				]
			},
			{
				"name": "Long UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "116fbbbb67efdb66c257763918ff03c2daca1a726a2559d0d5c31dc1"}
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
					{"type": "TEXT", "value": "abc", "encoding": "UTF8"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"}
				],
				"outputs" : [
					{"type": "HEX", "value": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
					{"type": "B64", "value": "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="}
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "encoding": "UTF8"},
					{"type": "HEX", "value": "6162636462636465636465666465666765666768666768696768696A68696A6B696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071"},
					{"type": "B64", "value": "YWJjZGJjZGVjZGVmZGVmZ2VmZ2hmZ2hpZ2hpamhpamtpamtsamtsbWtsbW5sbW5vbW5vcG5vcHE="}
				],
				"outputs" : [
					{"type": "HEX", "value": "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
					{"type": "B64", "value": "JI1qYdIGOLjlwCaTDD5gOaM85Flk/yFn9uzt1BnbBsE="}
				]
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF8"},
					{"type": "HEX", "value": millionaHex},
					{"type": "B64", "value": millionaB64}
				],
				"outputs" : [
					{"type": "HEX", "value": "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"},
					{"type": "B64", "value": "zcduXJkU+5KBocfihNc+Z/GAmkiklyAOBG05zMcRLNA="}
				]
			},
			{
				"name": "Short UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "e265e98c934ff1ff7d55359eed484c4581b3c372bac922350c645fb5fd937280"}
				]
			},
			{
				"name": "Medium UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "1d04116da99940f5eb149d21c7a556e1625839dd7fd74bcf4c3028b97b9da57f"}
				]
			},
			{
				"name": "Long UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "b21c3efa2f1a0075d566f7354aa51f0156e66ed209ee708902aa5953a7eb8140"}
				]
			},
			{
				"name": "Short UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "13e228567e8249fce53337f25d7970de3bd68ab2653424c7b8f9fd05e33caedf"}
				]
			},
			{
				"name": "Medium UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "fa84fa96dd6f1a0fda1769cacec9bac12efadad72ab60ff68ec5ae1a4d3fab8e"}
				]
			},
			{
				"name": "Long UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "a0bc50078623514a87e96de81d8d200527a1b1150acd92252d88aa109dfa0aa4"}
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
					{"type": "TEXT", "value": "abc", "encoding": "UTF8"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"}
				],
				"outputs" : [
					{"type": "HEX", "value": "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"},
					{"type": "B64", "value": "Ophdp0/iJbIEXBcta9OQvYVfCG4+nVJbRr/iRRFDFTI="}
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "encoding": "UTF8"},
					{"type": "HEX", "value": "6162636462636465636465666465666765666768666768696768696A68696A6B696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071"},
					{"type": "B64", "value": "YWJjZGJjZGVjZGVmZGVmZ2VmZ2hmZ2hpZ2hpamhpamtpamtsamtsbWtsbW5sbW5vbW5vcG5vcHE="}
				],
				"outputs" : [
					{"type": "HEX", "value": "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"},
					{"type": "B64", "value": "QcDboqnWJAhJEAN2qCNeLILhuZmKmZ4h2zLdl0ltM3Y="}
				]
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF8"},
					{"type": "HEX", "value": millionaHex},
					{"type": "B64", "value": millionaB64}
				],
				"outputs" : [
					{"type": "HEX", "value": "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"},
					{"type": "B64", "value": "XIh1rkdKNjS6T9VeyFv/1mHzKsp1xtaZ0M3LbBFYkcE="}
				]
			},
			{
				"name": "Short UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "a3198ab574d5b50d1a9aa1e34dbdaaa50ed6df67031bf66838e9c8b902a05feb"}
				]
			},
			{
				"name": "Medium UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "5cbbd5115111f239eaa31c106c3497e785bfe49dcae896642aa6e21f631bd4d5"}
				]
			},
			{
				"name": "Long UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "a9cd30fe7649d1c0d8ba700d01fde163a95e2bccb68c3faae8cc300c44264725"}
				]
			},
			{
				"name": "Short UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "a7fc119e08d5dbcdbd7f69d7bba10866c62ba2a3e31577a7d7c582f4ec20b78b"}
				]
			},
			{
				"name": "Medium UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "86037e690b1baa71450a0c2314cacbb08e0c571019f7f1f98aac1921c2d53889"}
				]
			},
			{
				"name": "Long UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "73b713b341e839a18e5ad439771ab52a71656662a0c019d9d1dcf9b001819a57"}
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
					{"type": "TEXT", "value": "abc", "encoding": "UTF8"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"}
				],
				"outputs" : [
					{"type": "HEX", "value": "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
					{"type": "B64", "value": "ywB1P0WjXou1oD1pmsZQBycsMqsO3tFjGotgWkP/W+2AhgcroefMI1i67KE0yCWn"}
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "encoding": "UTF8"},
					{"type": "HEX", "value": "61626364656667686263646566676869636465666768696A6465666768696A6B65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E6F696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F707172736D6E6F70717273746E6F707172737475"},
					{"type": "B64", "value": "YWJjZGVmZ2hiY2RlZmdoaWNkZWZnaGlqZGVmZ2hpamtlZmdoaWprbGZnaGlqa2xtZ2hpamtsbW5oaWprbG1ub2lqa2xtbm9wamtsbW5vcHFrbG1ub3Bxcmxtbm9wcXJzbW5vcHFyc3Rub3BxcnN0dQ=="}
				],
				"outputs" : [
					{"type": "HEX", "value": "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"},
					{"type": "B64", "value": "CTMMM/cRR+g9GS/Hgs0bR1MRGxc7OwXSL6CAhuOw9xL8x8caVX4tuWbD6fqRdGA5"}
				]
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF8"},
					{"type": "HEX", "value": millionaHex},
					{"type": "B64", "value": millionaB64}
				],
				"outputs" : [
					{"type": "HEX", "value": "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"},
					{"type": "B64", "value": "nQ4YCXFkdMsIboNOMQpKHO0UnpwA8khSeXLOxXBMKlsHuLPcOOzE666X3dh/PYmF"}
				]
			},
			{
				"name": "Short UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "46591d403db207914d0cc5b58ad3c665e79fd957753594cf815d28b7115fe776395643a49d15ab8f4e24c13a36cdb9ec"}
				]
			},
			{
				"name": "Medium UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "71a48b0abb2245253c2bb9fcebb4e7149a9b214b8598d11352b9a3e07de1f35c059c8153545070229d19880af122aa48"}
				]
			},
			{
				"name": "Long UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "e26cb55351464f57b23def3b2447281dc8ba4e38f543b20bf7ba026f1f2bea57d54d3a721dd97337a8022a26bbef2c49"}
				]
			},
			{
				"name": "Short UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "9b7ce7c7af46e400a37c8099cb4bbb5d0408061dd74cdb5dac7661bed1e53724bd07f299e265f400802a48d2e0b2092c"}
				]
			},
			{
				"name": "Medium UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "3c5fbafef52900a32840433c972999429d5c157426fdfb5c4968278f25bd4fe4f3b7aee8ae060695b05f61e595609637"}
				]
			},
			{
				"name": "Long UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "85056c62b9b2eba33a1ea69d06e32e71715188b25d3f7a2bc37be377890c4b0c08e7f55bc83550f0fe27a209088bc671"}
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
					{"type": "TEXT", "value": "abc", "encoding": "UTF8"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"}
				],
				"outputs" : [
					{"type": "HEX", "value": "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"},
					{"type": "B64", "value": "7AFJgohRb8kmRZ9Y4satjfm0c8sPwIwlltp88OSb5LKY2IzqknrH9Tnx7fIoN20l"}
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "encoding": "UTF8"},
					{"type": "HEX", "value": "61626364656667686263646566676869636465666768696A6465666768696A6B65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E6F696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F707172736D6E6F70717273746E6F707172737475"},
					{"type": "B64", "value": "YWJjZGVmZ2hiY2RlZmdoaWNkZWZnaGlqZGVmZ2hpamtlZmdoaWprbGZnaGlqa2xtZ2hpamtsbW5oaWprbG1ub2lqa2xtbm9wamtsbW5vcHFrbG1ub3Bxcmxtbm9wcXJzbW5vcHFyc3Rub3BxcnN0dQ=="}
				],
				"outputs" : [
					{"type": "HEX", "value": "79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7"},
					{"type": "B64", "value": "eUB9O1kWtZw+MLCYIpdHkcMT+57MhJ5AbyNZLQT2JdyMcJuYtDs4UrM3IWF5qn/H"}
				]
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF8"},
					{"type": "HEX", "value": millionaHex},
					{"type": "B64", "value": millionaB64}
				],
				"outputs" : [
					{"type": "HEX", "value": "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340"},
					{"type": "B64", "value": "7uniTXjBhVM3mDRR35fIrZ7t8lbGM0+OlI0lLV4OdoR6oHdN25CoQhkNLFWLS4NA"}
				]
			},
			{
				"name": "Short UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "1f7807100bfb7293a3f94c1b410b9d413497ad81ec7032442f72c832891a251632dcda5c5b3b63233b71c6305379fe3d"}
				]
			},
			{
				"name": "Medium UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "b43e4a80f5ac9cf4f555dcca7b5a0cc0c7bf6f14ea30dbef4c7db98d18f159536a4211b31aaca5157f4fbae599ced799"}
				]
			},
			{
				"name": "Long UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "91f1c447390dd54913eceab5d1036b55d6cedd2a1cee7f99627d7183a6f3125632689aa3e4716a8e96a57b2da1fef69a"}
				]
			},
			{
				"name": "Short UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "3f41b737dcc1e28410b9ad759f3687b31703247d36e98f3e1d96b1725d798d4e9c58a50e6217d4410d0ea81bc788f7b8"}
				]
			},
			{
				"name": "Medium UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "4bb8558d278d4e5b3b26e4173acc2c55a840f74ceb5ae0d9533eee416c3d3b1b4772ab0f0499e47fd03e0b4d579790f6"}
				]
			},
			{
				"name": "Long UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "ea60905cf5146f377d87be1e7774d9dfdf9500722023efbf5602b511417e44b69a5518b26f944eff8a97cfa662adfa01"}
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
					{"type": "TEXT", "value": "abc", "encoding": "UTF8"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"}
				],
				"outputs" : [
					{"type": "HEX", "value": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
					{"type": "B64", "value": "3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw=="}
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "encoding": "UTF8"},
					{"type": "HEX", "value": "61626364656667686263646566676869636465666768696A6465666768696A6B65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E6F696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F707172736D6E6F70717273746E6F707172737475"},
					{"type": "B64", "value": "YWJjZGVmZ2hiY2RlZmdoaWNkZWZnaGlqZGVmZ2hpamtlZmdoaWprbGZnaGlqa2xtZ2hpamtsbW5oaWprbG1ub2lqa2xtbm9wamtsbW5vcHFrbG1ub3Bxcmxtbm9wcXJzbW5vcHFyc3Rub3BxcnN0dQ=="}
				],
				"outputs" : [
					{"type": "HEX", "value": "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"},
					{"type": "B64", "value": "jpWbddrjE9qM9PcoFPwUP493ecbrn3+hcpmurbaIkBhQHSieSQD35DMbmd7EtUM6x9Mp7rbdJlReluVbh0vpCQ=="}
				]
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF8"},
					{"type": "HEX", "value": millionaHex},
					{"type": "B64", "value": millionaB64}
				],
				"outputs" : [
					{"type": "HEX", "value": "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"},
					{"type": "B64", "value": "5xhIPQznaWROLkLHvBW0Y44fmLE7IEQoVjKoA6+pc+veD/JEh36mCkywQyzld8Mb6wCcXCxJqi5OrbIXrYzAmw=="}
				]
			},
			{
				"name": "Short UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "cec00c412e5fe0ab4ff6ee7da097cce9b9ee67c8eeb3e99e11aec89dff1b8a2e417e37369c9c1bd65ce70f1b6be1ebf4ddbcaf2312fded40260fd55cf2ffe097"}
				]
			},
			{
				"name": "Medium UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "8f56290fb4a9cabfc427c0998abbef6527112db8c6916a9908421d97c820880b7a4137b29b7f6449b8f92a7666d85741faa01bdadb9b5d588570227b9be83360"}
				]
			},
			{
				"name": "Long UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "c89b6863e6568833664c449879f42fbe3e72b8054a43af61885904f72cebcc1a49b0d776b571cbf44530a291b5f5e2e26d8daa50047e5f0efc0b8e01a2ae6a08"}
				]
			},
			{
				"name": "Short UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "add8b8154df7a734d2947a981f4e61c5366710d610040e5b54894d1006e89283cba082287ed5dd4c25cdaa5af56d24ab9fbedc56897130b0b5f3e50c7f9ee6df"}
				]
			},
			{
				"name": "Medium UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "d14cbc5ecfd355acf9d181ee878b91db4f30a7b03f7904388f252a77b1fffa9feb96803698294556ff7ce87ad0ab3ae748df979603733105ff3ac038e51483a3"}
				]
			},
			{
				"name": "Long UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "5e6b9aa02688b69fe5ebe842aeab69b22144d815ca603051f2e61ab752d202f85dc54252d19f9d62381a2d5e88ab391b7c6565d5e0d39925a4ad5b07e99925bd"}
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
					{"type": "TEXT", "value": "abc", "encoding": "UTF8"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"}
				],
				"outputs" : [
					{"type": "HEX", "value": "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"},
					{"type": "B64", "value": "t1GFCxpXFopWk82SS2sJbgj2IYJ0RPcNiE9dAkDScS4Q4RbpGSrzyRp+xXZH45NAVzQLTPQI1aVlkvgnTuxT8A=="}
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "encoding": "UTF8"},
					{"type": "HEX", "value": "61626364656667686263646566676869636465666768696A6465666768696A6B65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E6F696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F707172736D6E6F70717273746E6F707172737475"},
					{"type": "B64", "value": "YWJjZGVmZ2hiY2RlZmdoaWNkZWZnaGlqZGVmZ2hpamtlZmdoaWprbGZnaGlqa2xtZ2hpamtsbW5oaWprbG1ub2lqa2xtbm9wamtsbW5vcHFrbG1ub3Bxcmxtbm9wcXJzbW5vcHFyc3Rub3BxcnN0dQ=="}
				],
				"outputs" : [
					{"type": "HEX", "value": "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185"},
					{"type": "B64", "value": "r+uy71QuZXnFDK0G0uV4+fjdaIHX3IJNJjYP7r8YpPpz4yYRIpSO/P1JLnToLiGJ7Q+0QNGH84InDLRV8h3RhQ=="}
				]
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF8"},
					{"type": "HEX", "value": millionaHex},
					{"type": "B64", "value": millionaB64}
				],
				"outputs" : [
					{"type": "HEX", "value": "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87"},
					{"type": "B64", "value": "PDqHbaFANKtgYnwHe7mPfhIKKlNwIS3/szhaGNTziFntMR0KnVFBzpzFxm7mibJmqKoYrOgoKg4NtZbJCwp7hw=="}
				]
			},
			{
				"name": "Short UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "e056f3f5c960c7adb4d8c45e6b91604ecd0d98e7f082dc63ace7da388fb9908ccf8a548cbcf8de7b069aa5c1005f09a4d8a28dcec324801b565673342e74caf1"}
				]
			},
			{
				"name": "Medium UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "b10dd0b98cbd73190e06b5720404cfb0f122a0ff7f063ad4a6ed6ed609eb5e1d3c87260ecc7b877fdf6592dc521c845ae06a5e106928e90f4021bac16c030a8d"}
				]
			},
			{
				"name": "Long UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "5f0b393b1a9bc521289a721291a860d95af6c420a1a16b0810d203870a1b37a0d047e000de95208d63fb373d2207dfd0cde5024692aebfd947e78c6c3ddd5ed8"}
				]
			},
			{
				"name": "Short UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "115fbb697dc2dcbcb61888d910a34d01162842f5329ead230870e98bcb75afb516b6440241f51192b7a67f6788b6396201dab5f205d6cd940312bcfe958b8aaa"}
				]
			},
			{
				"name": "Medium UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "ebe4b4d745a02d3fe56f23d38b6cf2674b4684696704586fc95f7be033c1140a9bdd530f80b867f3e927d1eb24969c8a2bb385ba0596e4ae1e0c2d84eff7266c"}
				]
			},
			{
				"name": "Long UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "b17e56d64e29cbe22943719ff00912b9866e6d372a6fe19130e7e2bb6d8572d002f8be5a547b1774c542e1089131a64106f5b687da295a3a92ec941301622596"}
				]
			}
		]
	},
	{
		"hash": "SHAKE128",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF8"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"}
				],
				"outputs" : [
					{"type": "HEX", "value": "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2c", "shakeLen": 248},
					{"type": "B64", "value": "WIEJLdgYv1z4o923k/vLp0CX1cUmptNfl7gzUZQPLA==", "shakeLen": 248},
					{"type": "HEX", "value": "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc844c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca5783", "shakeLen": 504},
					{"type": "B64", "value": "WIEJLdgYv1z4o923k/vLp0CX1cUmptNfl7gzUZQPLMhExQrzKs0/LN0GZWhwb1Cbwb3eWCldrj+JGpoPyleD", "shakeLen": 504}
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "encoding": "UTF8"},
					{"type": "HEX", "value": "61626364656667686263646566676869636465666768696A6465666768696A6B65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E6F696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F707172736D6E6F70717273746E6F707172737475"},
					{"type": "B64", "value": "YWJjZGVmZ2hiY2RlZmdoaWNkZWZnaGlqZGVmZ2hpamtlZmdoaWprbGZnaGlqa2xtZ2hpamtsbW5oaWprbG1ub2lqa2xtbm9wamtsbW5vcHFrbG1ub3Bxcmxtbm9wcXJzbW5vcHFyc3Rub3BxcnN0dQ=="}
				],
				"outputs" : [
					{"type": "HEX", "value": "7b6df6ff181173b6d7898d7ff63fb07b7c237daf471a5ae5602adbccef9ccf", "shakeLen": 248},
					{"type": "B64", "value": "e232/xgRc7bXiY1/9j+we3wjfa9HGlrlYCrbzO+czw==", "shakeLen": 248},
					{"type": "HEX", "value": "7b6df6ff181173b6d7898d7ff63fb07b7c237daf471a5ae5602adbccef9ccf4b37e06b4a3543164ffbe0d0557c02f9b25ad434005526d88ca04a6094b93ee5", "shakeLen": 504},
					{"type": "B64", "value": "e232/xgRc7bXiY1/9j+we3wjfa9HGlrlYCrbzO+cz0s34GtKNUMWT/vg0FV8AvmyWtQ0AFUm2IygSmCUuT7l", "shakeLen": 504}
				]
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF8"},
					{"type": "HEX", "value": millionaHex},
					{"type": "B64", "value": millionaB64}
				],
				"outputs" : [
					{"type": "HEX", "value": "9d222c79c4ff9d092cf6ca86143aa411e369973808ef97093255826c5572ef", "shakeLen": 248},
					{"type": "B64", "value": "nSIsecT/nQks9sqGFDqkEeNplzgI75cJMlWCbFVy7w==", "shakeLen": 248},
					{"type": "HEX", "value": "9d222c79c4ff9d092cf6ca86143aa411e369973808ef97093255826c5572ef58424c4b5c28475ffdcf981663867fec6321c1262e387bccf8ca676884c4a9d0", "shakeLen": 504},
					{"type": "B64", "value": "nSIsecT/nQks9sqGFDqkEeNplzgI75cJMlWCbFVy71hCTEtcKEdf/c+YFmOGf+xjIcEmLjh7zPjKZ2iExKnQ", "shakeLen": 504}
				]
			},
			{
				"name": "Short UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "40f2bdd295c3208f7f2f3436d2cab325ac0e7f204e04430853fdc217db767b", "shakeLen": 248},
					{"type": "HEX", "value": "40f2bdd295c3208f7f2f3436d2cab325ac0e7f204e04430853fdc217db767b9bb579eb6534f387de5c79544d0761849870d332aad8bf94d4ffc2c1e638ea47", "shakeLen": 504}
				]
			},
			{
				"name": "Medium UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "d8ccc8505c54a81ddafd0db03b7eb8c2f309655b980781629b04bc4e9d7dbf", "shakeLen": 248},
					{"type": "HEX", "value": "d8ccc8505c54a81ddafd0db03b7eb8c2f309655b980781629b04bc4e9d7dbf4a708b19fa12e434749880492d6c2dfd3deda5ae42c44c760f0faaf1b2ee31aa", "shakeLen": 504}
				]
			},
			{
				"name": "Long UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "29d48c0b789a3039977b97ebe61c8e963e2a1128acefd2301b476f7625630e", "shakeLen": 248},
					{"type": "HEX", "value": "29d48c0b789a3039977b97ebe61c8e963e2a1128acefd2301b476f7625630e0fb6660aaaa4103ef05246d4a5e52dbd08c8fa5fcc61e9c05aedbdc3289d91d1", "shakeLen": 504}
				]
			},
			{
				"name": "Short UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "6a426b1cd7f9cc84a2194ca196cff2642a730356065484756827a5c9615659", "shakeLen": 248},
					{"type": "HEX", "value": "6a426b1cd7f9cc84a2194ca196cff2642a730356065484756827a5c96156591c195572879ae4c2c2a4345b20cee264c18188c3033a45238d01fb6fcbfb2b44", "shakeLen": 504}
				]
			},
			{
				"name": "Medium UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "c589c37bdd19b37c96b650ce2622a7914d8b0d5ecb7855c77bd9b723a0c73b", "shakeLen": 248},
					{"type": "HEX", "value": "c589c37bdd19b37c96b650ce2622a7914d8b0d5ecb7855c77bd9b723a0c73be880392931a248a5ce89338d0f46e837adde144d8a0780625599477adff6a124", "shakeLen": 504}
				]
			},
			{
				"name": "Long UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "fe68432164f01f9b90a715299126d6b50787e50691a0c4b1af01243bcbf283", "shakeLen": 248},
					{"type": "HEX", "value": "fe68432164f01f9b90a715299126d6b50787e50691a0c4b1af01243bcbf2837f94a8275fcd414c244505ad9709c78ff53578fe06ef69ba1195394a50d1b4f7", "shakeLen": 504}
				]
			}
		]
	},
	{
		"hash": "SHAKE256",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF8"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"}
				],
				"outputs" : [
					{"type": "HEX", "value": "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b57", "shakeLen": 248},
					{"type": "B64", "value": "SDNmYBNgqHccaGMIDMQRTY20RTD48eHuT5TqN+eLVw==", "shakeLen": 248},
					{"type": "HEX", "value": "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751", "shakeLen": 504},
					{"type": "B64", "value": "SDNmYBNgqHccaGMIDMQRTY20RTD48eHuT5TqN+eLVznVoVvvGGpThsdXRMBSfh+qn4cm5GKhKk/rBr2IAedR", "shakeLen": 504}
				]
			},
			{
				"name": "Medium",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "encoding": "UTF8"},
					{"type": "HEX", "value": "61626364656667686263646566676869636465666768696A6465666768696A6B65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E6F696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F707172736D6E6F70717273746E6F707172737475"},
					{"type": "B64", "value": "YWJjZGVmZ2hiY2RlZmdoaWNkZWZnaGlqZGVmZ2hpamtlZmdoaWprbGZnaGlqa2xtZ2hpamtsbW5oaWprbG1ub2lqa2xtbm9wamtsbW5vcHFrbG1ub3Bxcmxtbm9wcXJzbW5vcHFyc3Rub3BxcnN0dQ=="}
				],
				"outputs" : [
					{"type": "HEX", "value": "98be04516c04cc73593fef3ed0352ea9f6443942d6950e29a372a681c3deaf", "shakeLen": 248},
					{"type": "B64", "value": "mL4EUWwEzHNZP+8+0DUuqfZEOULWlQ4po3KmgcPerw==", "shakeLen": 248},
					{"type": "HEX", "value": "98be04516c04cc73593fef3ed0352ea9f6443942d6950e29a372a681c3deaf4535423709b02843948684e029010badcc0acd8303fc85fdad3eabf4f78cae16", "shakeLen": 504},
					{"type": "B64", "value": "mL4EUWwEzHNZP+8+0DUuqfZEOULWlQ4po3KmgcPer0U1QjcJsChDlIaE4CkBC63MCs2DA/yF/a0+q/T3jK4W", "shakeLen": 504}
				]
			},
			{
				"name": "Long",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF8"},
					{"type": "HEX", "value": millionaHex},
					{"type": "B64", "value": millionaB64}
				],
				"outputs" : [
					{"type": "HEX", "value": "3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234dfd1", "shakeLen": 248},
					{"type": "B64", "value": "NXinpMqRN1ac33btYX0xu5lPypwbv4sYQBPegjTf0Q==", "shakeLen": 248},
					{"type": "HEX", "value": "3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234dfd13a3fd124d4df76c0a539ee7dd2f6e1ec346124c815d9410e145eb561bcd97b18", "shakeLen": 504},
					{"type": "B64", "value": "NXinpMqRN1ac33btYX0xu5lPypwbv4sYQBPegjTf0To/0STU33bApTnufdL24ew0YSTIFdlBDhRetWG82XsY", "shakeLen": 504}
				]
			},
			{
				"name": "Short UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "a8e58b37e3dab187c7c20123870900aa11fee5f0c3bbba8af2edc6e892b429", "shakeLen": 248},
					{"type": "HEX", "value": "a8e58b37e3dab187c7c20123870900aa11fee5f0c3bbba8af2edc6e892b42984543e4ba39cd6661a22a785dcf6531f7275be0b47d6c9690475ce347e00da58", "shakeLen": 504}
				]
			},
			{
				"name": "Medium UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "262903200110b573ba851475488f5b751dcba77579d436180d9efccfc93b91", "shakeLen": 248},
					{"type": "HEX", "value": "262903200110b573ba851475488f5b751dcba77579d436180d9efccfc93b912c4d70f115c9bf3fdbb133e34f23768fa57151f54135d7c681a5e2cf1b5129d0", "shakeLen": 504}
				]
			},
			{
				"name": "Long UTF16-BE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16BE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "25444b2108287ee102e524a9499103bd87f9ae7e82b18777e8c84e2834ce0b", "shakeLen": 248},
					{"type": "HEX", "value": "25444b2108287ee102e524a9499103bd87f9ae7e82b18777e8c84e2834ce0b4d38350f3c0536fb12ec9f0109397b520abf249a17dcbe33421c5abf21f23cdb", "shakeLen": 504}
				]
			},
			{
				"name": "Short UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abc", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "d94f7da7db99cfbb32bc5fa89917a60dc1c12f46c924bcac76b05bb9eefa70", "shakeLen": 248},
					{"type": "HEX", "value": "d94f7da7db99cfbb32bc5fa89917a60dc1c12f46c924bcac76b05bb9eefa705f909795f964f22e2036ccb560d952f1485d75127b060d680e19efb0bf852cf9", "shakeLen": 504}
				]
			},
			{
				"name": "Medium UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "cade3014570c222dc6aa327be04ac8088f85fe0a177f08e48b24b6a30dc078", "shakeLen": 248},
					{"type": "HEX", "value": "cade3014570c222dc6aa327be04ac8088f85fe0a177f08e48b24b6a30dc0783fd4bdef46fddd440dba74b8dd5b524b9530d85e2a30e2e35a1bee69f7c7ed9a", "shakeLen": 504}
				]
			},
			{
				"name": "Long UTF16-LE",
				"ptInputs": [
					{"type": "TEXT", "value": millionaAscii, "encoding": "UTF16LE"}
				],
				"outputs" : [
					{"type": "HEX", "value": "295697f761094a339fc6626b97f10d89912839d276ab7a1bf330eb3c40baad", "shakeLen": 248},
					{"type": "HEX", "value": "295697f761094a339fc6626b97f10d89912839d276ab7a1bf330eb3c40baad9d21210c4847df516ec630ae7077a9a17f0d6792561d7708068a3d32850c8cca", "shakeLen": 504}
				]
			}
		]
	}
];

/* Dynamically build ArrayBuffer tests if the environment supports them */
try
{
	hashTests.forEach(function(testSuite) {
		testSuite["tests"].forEach(function(test) {
			var clonedOutputs = [];
			test["ptInputs"].forEach(function(ptInput) {
				if (ptInput["type"] === "HEX")
				{
					test["ptInputs"].push({"type": "ARRAYBUFFER", "value": hexToArrayBuffer(ptInput["value"])});
				}
			});
			test["outputs"].forEach(function(output) {
				if (output["type"] === "HEX")
				{
					/* Can't compare ARRAYBUFFERs so actually use the HEX output directly and convert in the unit test */
					if (output.hasOwnProperty("shakeLen"))
					{
						clonedOutputs.push({"type": "ARRAYBUFFER", "value": output["value"], "shakeLen": output["shakeLen"]});
					}
					else
					{
						clonedOutputs.push({"type": "ARRAYBUFFER", "value": output["value"]});
					}
				}
			});
			test["outputs"] = test["outputs"].concat(clonedOutputs);
		});
	});
}
catch (ignore)
{
	/* ArrayBuffers may not be supported by the environment */
}

hashTests.forEach(function(testSuite) {
	describe("Basic " + testSuite["hash"] + " Tests", function() {
		try
		{
			testSuite["tests"].forEach(function(test) {
				test["ptInputs"].forEach(function(ptInput) {
					var inOptions = {}, hash = null;
					if (ptInput.hasOwnProperty("encoding"))
					{
						inOptions["encoding"] = ptInput["encoding"];
					}
					hash = new jsSHA(testSuite["hash"], ptInput["type"], inOptions);
					hash.update(ptInput["value"]);

					test["outputs"].forEach(function(output) {
						var outOptions = {};
						if (output.hasOwnProperty("shakeLen"))
						{
							outOptions["shakeLen"] = output["shakeLen"];
						}

						if (output["type"] != "ARRAYBUFFER")
						{
							it(test["name"] + " " + ptInput["type"] + " Input - " + output["type"] + " Output", function() {
								chai.assert.equal(hash.getHash(output["type"], outOptions), output["value"]);
							});
						}
						else /* Matching the dynamic build of ArrayBuffer tests, need to use HEX as a comparison medium */
						{
							it(test["name"] + " " + ptInput["type"] + " Input - " + output["type"] + " Output", function() {
								chai.assert.equal(arrayBufferToHex(hash.getHash(output["type"], outOptions)), output["value"]);
							});
						}
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
