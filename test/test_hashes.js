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
		"hash": "SHA3-224",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "abc"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"},
				],
				"outputs" : [
					{"type": "HEX", "value": "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"},
					{"type": "B64", "value": "5kKCTD+M8krQkjTufTx2b8mjpRaNDJStc7Rv3w=="},
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
					{"type": "HEX", "value": "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33"},
					{"type": "B64", "value": "iiQQixVK2iHJ/VV0SUR5ulx+erdu8mTq0PzOMw=="},
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
					{"type": "HEX", "value": "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c"},
					{"type": "B64", "value": "1pM1uTMlGS5RapEubRmhXLUcbtXBUkPnp/1lPA=="},
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
		"hash": "SHA3-256",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "abc"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"},
				],
				"outputs" : [
					{"type": "HEX", "value": "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"},
					{"type": "B64", "value": "Ophdp0/iJbIEXBcta9OQvYVfCG4+nVJbRr/iRRFDFTI="},
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
					{"type": "HEX", "value": "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"},
					{"type": "B64", "value": "QcDboqnWJAhJEAN2qCNeLILhuZmKmZ4h2zLdl0ltM3Y="},
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
					{"type": "HEX", "value": "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"},
					{"type": "B64", "value": "XIh1rkdKNjS6T9VeyFv/1mHzKsp1xtaZ0M3LbBFYkcE="},
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
		"hash": "SHA3-384",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "abc"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"},
				],
				"outputs" : [
					{"type": "HEX", "value": "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"},
					{"type": "B64", "value": "7AFJgohRb8kmRZ9Y4satjfm0c8sPwIwlltp88OSb5LKY2IzqknrH9Tnx7fIoN20l"},
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
					{"type": "HEX", "value": "79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7"},
					{"type": "B64", "value": "eUB9O1kWtZw+MLCYIpdHkcMT+57MhJ5AbyNZLQT2JdyMcJuYtDs4UrM3IWF5qn/H"},
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
					{"type": "HEX", "value": "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340"},
					{"type": "B64", "value": "7uniTXjBhVM3mDRR35fIrZ7t8lbGM0+OlI0lLV4OdoR6oHdN25CoQhkNLFWLS4NA"},
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
	},
	{
		"hash": "SHA3-512",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "abc"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"},
				],
				"outputs" : [
					{"type": "HEX", "value": "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"},
					{"type": "B64", "value": "t1GFCxpXFopWk82SS2sJbgj2IYJ0RPcNiE9dAkDScS4Q4RbpGSrzyRp+xXZH45NAVzQLTPQI1aVlkvgnTuxT8A=="},
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
					{"type": "HEX", "value": "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185"},
					{"type": "B64", "value": "r+uy71QuZXnFDK0G0uV4+fjdaIHX3IJNJjYP7r8YpPpz4yYRIpSO/P1JLnToLiGJ7Q+0QNGH84InDLRV8h3RhQ=="},
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
					{"type": "HEX", "value": "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87"},
					{"type": "B64", "value": "PDqHbaFANKtgYnwHe7mPfhIKKlNwIS3/szhaGNTziFntMR0KnVFBzpzFxm7mibJmqKoYrOgoKg4NtZbJCwp7hw=="},
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
					{"type": "TEXT", "value": "abc"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"},
				],
				"outputs" : [
					{"type": "HEX", "value": "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2c", "shakeLen": 248},
					{"type": "B64", "value": "WIEJLdgYv1z4o923k/vLp0CX1cUmptNfl7gzUZQPLA==", "shakeLen": 248},
					{"type": "HEX", "value": "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc844c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca5783", "shakeLen": 504},
					{"type": "B64", "value": "WIEJLdgYv1z4o923k/vLp0CX1cUmptNfl7gzUZQPLMhExQrzKs0/LN0GZWhwb1Cbwb3eWCldrj+JGpoPyleD", "shakeLen": 504},
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
					{"type": "HEX", "value": "7b6df6ff181173b6d7898d7ff63fb07b7c237daf471a5ae5602adbccef9ccf", "shakeLen": 248},
					{"type": "B64", "value": "e232/xgRc7bXiY1/9j+we3wjfa9HGlrlYCrbzO+czw==", "shakeLen": 248},
					{"type": "HEX", "value": "7b6df6ff181173b6d7898d7ff63fb07b7c237daf471a5ae5602adbccef9ccf4b37e06b4a3543164ffbe0d0557c02f9b25ad434005526d88ca04a6094b93ee5", "shakeLen": 504},
					{"type": "B64", "value": "e232/xgRc7bXiY1/9j+we3wjfa9HGlrlYCrbzO+cz0s34GtKNUMWT/vg0FV8AvmyWtQ0AFUm2IygSmCUuT7l", "shakeLen": 504},
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
					{"type": "HEX", "value": "9d222c79c4ff9d092cf6ca86143aa411e369973808ef97093255826c5572ef", "shakeLen": 248},
					{"type": "B64", "value": "nSIsecT/nQks9sqGFDqkEeNplzgI75cJMlWCbFVy7w==", "shakeLen": 248},
					{"type": "HEX", "value": "9d222c79c4ff9d092cf6ca86143aa411e369973808ef97093255826c5572ef58424c4b5c28475ffdcf981663867fec6321c1262e387bccf8ca676884c4a9d0", "shakeLen": 504},
					{"type": "B64", "value": "nSIsecT/nQks9sqGFDqkEeNplzgI75cJMlWCbFVy71hCTEtcKEdf/c+YFmOGf+xjIcEmLjh7zPjKZ2iExKnQ", "shakeLen": 504},
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
					{"type": "TEXT", "value": "abc"},
					{"type": "HEX", "value": "616263"},
					{"type": "B64", "value": "YWJj"},
				],
				"outputs" : [
					{"type": "HEX", "value": "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b57", "shakeLen": 248},
					{"type": "B64", "value": "SDNmYBNgqHccaGMIDMQRTY20RTD48eHuT5TqN+eLVw==", "shakeLen": 248},
					{"type": "HEX", "value": "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751", "shakeLen": 504},
					{"type": "B64", "value": "SDNmYBNgqHccaGMIDMQRTY20RTD48eHuT5TqN+eLVznVoVvvGGpThsdXRMBSfh+qn4cm5GKhKk/rBr2IAedR", "shakeLen": 504},
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
					{"type": "HEX", "value": "98be04516c04cc73593fef3ed0352ea9f6443942d6950e29a372a681c3deaf", "shakeLen": 248},
					{"type": "B64", "value": "mL4EUWwEzHNZP+8+0DUuqfZEOULWlQ4po3KmgcPerw==", "shakeLen": 248},
					{"type": "HEX", "value": "98be04516c04cc73593fef3ed0352ea9f6443942d6950e29a372a681c3deaf4535423709b02843948684e029010badcc0acd8303fc85fdad3eabf4f78cae16", "shakeLen": 504},
					{"type": "B64", "value": "mL4EUWwEzHNZP+8+0DUuqfZEOULWlQ4po3KmgcPer0U1QjcJsChDlIaE4CkBC63MCs2DA/yF/a0+q/T3jK4W", "shakeLen": 504},
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
					{"type": "HEX", "value": "3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234dfd1", "shakeLen": 248},
					{"type": "B64", "value": "NXinpMqRN1ac33btYX0xu5lPypwbv4sYQBPegjTf0Q==", "shakeLen": 248},
					{"type": "HEX", "value": "3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234dfd13a3fd124d4df76c0a539ee7dd2f6e1ec346124c815d9410e145eb561bcd97b18", "shakeLen": 504},
					{"type": "B64", "value": "NXinpMqRN1ac33btYX0xu5lPypwbv4sYQBPegjTf0To/0STU33bApTnufdL24ew0YSTIFdlBDhRetWG82XsY", "shakeLen": 504},
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
						var options = {}, hash = new jsSHA(testSuite["hash"], ptInput["type"]);
						hash.update(ptInput["value"]);
						if (output.hasOwnProperty("shakeLen"))
						{
							options["shakeLen"] = output["shakeLen"]
						}
						it(test["name"] + " " + ptInput["type"] + " Input - " + output["type"] + " Output", function() {
							chai.assert.equal(hash.getHash(output["type"], options), output["value"]);
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
