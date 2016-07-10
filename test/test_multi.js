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
		"hash": "SHA3-224",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "abc"}
				],
				"outputs": [
					{"type": "HEX", "rounds": 5, "value": "7d208060760d239d9e9b041b5c30ac992b83ff1df658263953c9eff0"},
					{"type": "HEX", "rounds": 10, "value": "a1b668748fd69b8b6a6453d3bada2b9eb9a06a29b78fbcff5ab530ae"}
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
		"hash": "SHA3-256",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "abc"}
				],
				"outputs": [
					{"type": "HEX", "rounds": 5, "value": "fd5ad48a1abf3fd8211ecd2a6a0b0503e745d953def260541fa5db7dc1b3b84f"},
					{"type": "HEX", "rounds": 10, "value": "5b814fc96d03918994939bccb796945d9683fa90a22f99350d6a964de78a7980"}
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
		"hash": "SHA3-384",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "abc"}
				],
				"outputs": [
					{"type": "HEX", "rounds": 5, "value": "be2f2365cecd5df751f3ab7d23cabfb60491ce28bdf80b121f7941ee33227ce86d5d62d6633f5654a4f3ae5381cf1825"},
					{"type": "HEX", "rounds": 10, "value": "4cb125e919d39ab283964e06ce58dd8923fa599046b533958c9353317ab368066b9902c2e1a9c9376d66f321fcc2c0a1"}
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
	},
	{
		"hash": "SHA3-512",
		"tests": [
			{
				"name": "Short",
				"ptInputs": [
					{"type": "TEXT", "value": "abc"}
				],
				"outputs": [
					{"type": "HEX", "rounds": 5, "value": "8c74189ca608ad188bb96c8c374fb717ce982500dc2c0ce90ad8e5888b498ce9fda0e4bf256feeaaf1674b69e9ea80cf5ed444dfdd5d3eb05cfebd597b4aab67"},
					{"type": "HEX", "rounds": 10, "value": "0e3c0126a211563fdedc96149f1c2334aa5f5b2afcf5590cb71fec0ab348ba522e56c1136f165f525b22890e2546d2f9edbea6b6f5e929237b6c0f395e1b2e9b"}
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
					{"type": "TEXT", "value": "abc"}
				],
				"outputs": [
					{"type": "HEX", "rounds": 5, "value": "99d5aa0763f5bd9464ed4bbc631ecdac6f67e77cbf61c7f7171dd2ffa892ba", "shakeLen": 248},
					{"type": "HEX", "rounds": 10, "value": "5a5aeb2022e0e92ef4da3dc3e261a9303224b65cf6666f87a4d395a4ab94fe", "shakeLen": 248}
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
					{"type": "TEXT", "value": "abc"}
				],
				"outputs": [
					{"type": "HEX", "rounds": 5, "value": "70368c73548e76dd6405ea6c1b4358eb0aeb4c0efe73526c7c6e1d9a9e4e0a", "shakeLen": 248},
					{"type": "HEX", "rounds": 10, "value": "d706c35b6642f39a27635c61c85ab13e76827de8fde4557e25bfc96b445f10", "shakeLen": 248}
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
						var options = {}, hash = new jsSHA(testSuite["hash"], ptInput["type"], {"numRounds": output["rounds"]});
						hash.update(ptInput["value"]);
						it(test["name"] + " " + ptInput["type"] + " Input - " + output["type"] + " Output - " + output["rounds"] + " Rounds ", function() {
							if (output.hasOwnProperty("shakeLen"))
							{
								options["shakeLen"] = output["shakeLen"]
							}
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
				throw new Error("Testing of multi-round " + testSuite["hash"] + " failed");
			}
		}
	});
});
/* ============================================================================
 *                        End Multi-Round Hash Tests
 * ============================================================================
 */
