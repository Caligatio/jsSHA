/* globals module, define, self */
(function (global, factory) {
  typeof exports === "object" && typeof module !== "undefined"
    ? (module.exports = factory())
    : typeof define === "function" && define.amd
    ? define(factory)
    : ((global = global || self), (global.hashData = factory()));
})(this, function () {
  "use strict";

  /* This is used often so make a global copy that everything can reference */
  const millionaAscii = "a".repeat(1000000);

  const hash_data = {
    "SHA-1": [
      {
        name: "Short",
        input: { format: "TEXT", value: "abc", encoding: "UTF8" },
        outputs: [{ format: "HEX", value: "a9993e364706816aba3e25717850c26c9cd0d89d" }],
      },
      {
        name: "Medium",
        input: { format: "TEXT", value: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", encoding: "UTF8" },
        outputs: [{ format: "HEX", value: "84983e441c3bd26ebaae4aa1f95129e5e54670f1" }],
      },
      {
        name: "Long",
        input: { format: "TEXT", value: millionaAscii, encoding: "UTF8" },
        outputs: [{ format: "HEX", value: "34aa973cd4c4daa4f61eeb2bdbad27316534016f" }],
      },
      {
        name: "Short with 5 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 5, encoding: "UTF8" },
        outputs: [{ format: "HEX", rounds: 5, value: "b5c64925eb9940259be55c005c9cecc7d9897ef9" }],
      },
      {
        name: "Short with 10 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 10, encoding: "UTF8" },
        outputs: [{ format: "HEX", rounds: 10, value: "94ebc0d3c81b61eb98670666f5fde68560c4e165" }],
      },
      {
        name: "HMAC With Short Key",
        input: { format: "TEXT", value: "Sample message for keylen<blocklen" },
        hmacKey: { format: "HEX", value: "000102030405060708090A0B0C0D0E0F10111213" },
        outputs: [{ format: "HEX", value: "4c99ff0cb1b31bd33f8431dbaf4d17fcd356a807" }],
      },
      {
        name: "HMAC With Medium Key",
        input: { format: "TEXT", value: "Sample message for keylen=blocklen" },
        hmacKey: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        },
        outputs: [{ format: "HEX", value: "5fd596ee78d5553c8ff4e72d266dfd192366da29" }],
      },
      {
        name: "HMAC With Long Key",
        input: { format: "TEXT", value: "Sample message for keylen=blocklen" },
        hmacKey: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263",
        },
        outputs: [{ format: "HEX", value: "2d51b2f7750e410584662e38f133435f4c4fd42a" }],
      },
    ],
    "SHA-224": [
      {
        name: "Short",
        input: { format: "TEXT", value: "abc", encoding: "UTF8" },
        outputs: [{ format: "HEX", value: "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" }],
      },
      {
        name: "Medium",
        input: { format: "TEXT", value: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", encoding: "UTF8" },
        outputs: [{ format: "HEX", value: "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525" }],
      },
      {
        name: "Long",
        input: { format: "TEXT", value: millionaAscii, encoding: "UTF8" },

        outputs: [{ format: "HEX", value: "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67" }],
      },
      {
        name: "Short with 5 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 5, encoding: "UTF8" },
        outputs: [{ format: "HEX", rounds: 5, value: "5b4b17f720d52c6a864229e784fb636184ca48ce7dd848fdad986239" }],
      },
      {
        name: "Short with 10 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 10, encoding: "UTF8" },
        outputs: [{ format: "HEX", rounds: 10, value: "5230eb37afcc115f4f380a9f50c4743d457bbe586e6faa6bf21696f9" }],
      },
      {
        name: "HMAC With Short Key",
        input: { format: "TEXT", value: "Sample message for keylen<blocklen" },
        hmacKey: { format: "HEX", value: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B" },
        outputs: [{ format: "HEX", value: "e3d249a8cfb67ef8b7a169e9a0a599714a2cecba65999a51beb8fbbe" }],
      },
      {
        name: "HMAC With Medium Key",
        input: { format: "TEXT", value: "Sample message for keylen=blocklen" },
        hmacKey: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        },
        outputs: [{ format: "HEX", value: "c7405e3ae058e8cd30b08b4140248581ed174cb34e1224bcc1efc81b" }],
      },
      {
        name: "HMAC With Long Key",
        input: { format: "TEXT", value: "Sample message for keylen=blocklen" },
        hmacKey: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263",
        },
        outputs: [{ format: "HEX", value: "91c52509e5af8531601ae6230099d90bef88aaefb961f4080abc014d" }],
      },
    ],
    "SHA3-224": [
      {
        name: "Short",
        input: { format: "TEXT", value: "abc", encoding: "UTF8" },
        outputs: [{ format: "HEX", value: "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf" }],
      },
      {
        name: "Medium",
        input: { format: "TEXT", value: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", encoding: "UTF8" },
        outputs: [{ format: "HEX", value: "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33" }],
      },
      {
        name: "Long",
        input: { format: "TEXT", value: millionaAscii, encoding: "UTF8" },
        outputs: [{ format: "HEX", value: "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c" }],
      },
      {
        name: "Short with 5 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 5, encoding: "UTF8" },
        outputs: [{ format: "HEX", rounds: 5, value: "7d208060760d239d9e9b041b5c30ac992b83ff1df658263953c9eff0" }],
      },
      {
        name: "Short with 10 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 10, encoding: "UTF8" },
        outputs: [{ format: "HEX", rounds: 10, value: "a1b668748fd69b8b6a6453d3bada2b9eb9a06a29b78fbcff5ab530ae" }],
      },
      {
        name: "HMAC With Short Key",
        input: { format: "TEXT", value: "Sample message for keylen<blocklen" },
        hmacKey: { format: "HEX", value: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B" },
        outputs: [{ format: "HEX", value: "332cfd59347fdb8e576e77260be4aba2d6dc53117b3bfb52c6d18c04" }],
      },
      {
        name: "HMAC With Medium Key",
        input: { format: "TEXT", value: "Sample message for keylen=blocklen" },
        hmacKey: {
          format: "HEX",
          value:
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        },
        outputs: [{ format: "HEX", value: "d8b733bcf66c644a12323d564e24dcf3fc75f231f3b67968359100c7" }],
      },
      {
        name: "HMAC With Long Key",
        input: { format: "TEXT", value: "Sample message for keylen>blocklen" },
        hmacKey: {
          format: "HEX",
          value:
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaab",
        },
        outputs: [{ format: "HEX", value: "078695eecc227c636ad31d063a15dd05a7e819a66ec6d8de1e193e59" }],
      },
    ],
    "SHA-256": [
      {
        name: "Short",
        input: { format: "TEXT", value: "abc", encoding: "UTF8" },
        outputs: [{ format: "HEX", value: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" }],
      },
      {
        name: "Medium",
        input: { format: "TEXT", value: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", encoding: "UTF8" },
        outputs: [{ format: "HEX", value: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" }],
      },
      {
        name: "Long",
        input: { format: "TEXT", value: millionaAscii, encoding: "UTF8" },
        outputs: [{ format: "HEX", value: "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0" }],
      },
      {
        name: "Short with 5 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 5, encoding: "UTF8" },
        outputs: [
          { format: "HEX", rounds: 5, value: "184f6d6e82554c051b33f15e7ffffecb0cc0f461a29096c41c214e168e34c21d" },
        ],
      },
      {
        name: "Short with 10 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 10, encoding: "UTF8" },
        outputs: [
          { format: "HEX", rounds: 10, value: "10e286f907c0fe9f02cea3864cbaec04ae47e2c0a13b60473bc9968a4851b219" },
        ],
      },
      {
        name: "HMAC With Short Key",
        input: { format: "TEXT", value: "Sample message for keylen<blocklen" },
        hmacKey: { format: "HEX", value: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" },
        outputs: [{ format: "HEX", value: "a28cf43130ee696a98f14a37678b56bcfcbdd9e5cf69717fecf5480f0ebdf790" }],
      },
      {
        name: "HMAC With Medium Key",
        input: { format: "TEXT", value: "Sample message for keylen=blocklen" },
        hmacKey: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        },
        outputs: [{ format: "HEX", value: "8bb9a1db9806f20df7f77b82138c7914d174d59e13dc4d0169c9057b133e1d62" }],
      },
      {
        name: "HMAC With Long Key",
        input: { format: "TEXT", value: "Sample message for keylen=blocklen" },
        hmacKey: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263",
        },
        outputs: [{ format: "HEX", value: "bdccb6c72ddeadb500ae768386cb38cc41c63dbb0878ddb9c7a38a431b78378d" }],
      },
    ],
    "SHA3-256": [
      {
        name: "Short",
        input: { format: "TEXT", value: "abc", encoding: "UTF8" },
        outputs: [{ format: "HEX", value: "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532" }],
      },
      {
        name: "Medium",
        input: { format: "TEXT", value: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", encoding: "UTF8" },
        outputs: [{ format: "HEX", value: "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376" }],
      },
      {
        name: "Long",
        input: { format: "TEXT", value: millionaAscii, encoding: "UTF8" },
        outputs: [{ format: "HEX", value: "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1" }],
      },
      {
        name: "Short with 5 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 5, encoding: "UTF8" },
        outputs: [
          { format: "HEX", rounds: 5, value: "fd5ad48a1abf3fd8211ecd2a6a0b0503e745d953def260541fa5db7dc1b3b84f" },
        ],
      },
      {
        name: "Short with 10 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 10, encoding: "UTF8" },
        outputs: [
          { format: "HEX", rounds: 10, value: "5b814fc96d03918994939bccb796945d9683fa90a22f99350d6a964de78a7980" },
        ],
      },
      {
        name: "HMAC With Short Key",
        input: { format: "TEXT", value: "Sample message for keylen<blocklen" },

        hmacKey: { format: "HEX", value: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" },
        outputs: [{ format: "HEX", value: "4fe8e202c4f058e8dddc23d8c34e467343e23555e24fc2f025d598f558f67205" }],
      },
      {
        name: "HMAC With Medium Key",
        input: { format: "TEXT", value: "Sample message for keylen=blocklen" },
        hmacKey: {
          format: "HEX",
          value:
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384858687",
        },
        outputs: [{ format: "HEX", value: "68b94e2e538a9be4103bebb5aa016d47961d4d1aa906061313b557f8af2c3faa" }],
      },
      {
        name: "HMAC With Long Key",
        input: { format: "TEXT", value: "Sample message for keylen>blocklen" },
        hmacKey: {
          format: "HEX",
          value:
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7",
        },
        outputs: [{ format: "HEX", value: "9bcf2c238e235c3ce88404e813bd2f3a97185ac6f238c63d6229a00b07974258" }],
      },
    ],
    "SHA-384": [
      {
        name: "Short",
        input: { format: "TEXT", value: "abc", encoding: "UTF8" },
        outputs: [
          {
            format: "HEX",
            value: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
          },
        ],
      },
      {
        name: "Medium",
        input: {
          format: "TEXT",
          value:
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
          encoding: "UTF8",
        },
        outputs: [
          {
            format: "HEX",
            value: "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
          },
        ],
      },
      {
        name: "Long",
        input: { format: "TEXT", value: millionaAscii, encoding: "UTF8" },
        outputs: [
          {
            format: "HEX",
            value: "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
          },
        ],
      },
      {
        name: "Short with 5 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 5, encoding: "UTF8" },
        outputs: [
          {
            format: "HEX",
            rounds: 5,
            value: "a4aa4cd8534aecb2d07765f928303d1d2609835ea85d14312bcee264e99dc5d7dc08bb18ec694053fd7fe6906706d55f",
          },
        ],
      },
      {
        name: "Short with 10 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 10, encoding: "UTF8" },
        outputs: [
          {
            format: "HEX",
            rounds: 10,
            value: "b80c82979453f2f3dcf89ec4cef5c71e89837537de170e3942af8b37757cc790d4cc4ebe16a52164ad19f3a02d192f1c",
          },
        ],
      },
      {
        name: "HMAC With Short Key",
        input: { format: "TEXT", value: "Sample message for keylen<blocklen" },
        hmacKey: {
          format: "HEX",
          value: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F",
        },
        outputs: [
          {
            format: "HEX",
            value: "6eb242bdbb582ca17bebfa481b1e23211464d2b7f8c20b9ff2201637b93646af5ae9ac316e98db45d9cae773675eeed0",
          },
        ],
      },
      {
        name: "HMAC With Medium Key",
        input: { format: "TEXT", value: "Sample message for keylen=blocklen" },
        hmacKey: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
        },
        outputs: [
          {
            format: "HEX",
            value: "63c5daa5e651847ca897c95814ab830bededc7d25e83eef9195cd45857a37f448947858f5af50cc2b1b730ddf29671a9",
          },
        ],
      },
      {
        name: "HMAC With Long Key",
        input: { format: "TEXT", value: "Sample message for keylen=blocklen" },
        hmacKey: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
        },
        outputs: [
          {
            format: "HEX",
            value: "5b664436df69b0ca22551231a3f0a3d5b4f97991713cfa84bff4d0792eff96c27dccbbb6f79b65d548b40e8564cef594",
          },
        ],
      },
    ],
    "SHA3-384": [
      {
        name: "Short",
        input: { format: "TEXT", value: "abc", encoding: "UTF8" },
        outputs: [
          {
            format: "HEX",
            value: "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
          },
        ],
      },
      {
        name: "Medium",
        input: {
          format: "TEXT",
          value:
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
          encoding: "UTF8",
        },
        outputs: [
          {
            format: "HEX",
            value: "79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7",
          },
        ],
      },
      {
        name: "Long",
        input: { format: "TEXT", value: millionaAscii, encoding: "UTF8" },
        outputs: [
          {
            format: "HEX",
            value: "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340",
          },
        ],
      },
      {
        name: "Short with 5 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 5, encoding: "UTF8" },
        outputs: [
          {
            format: "HEX",
            rounds: 5,
            value: "be2f2365cecd5df751f3ab7d23cabfb60491ce28bdf80b121f7941ee33227ce86d5d62d6633f5654a4f3ae5381cf1825",
          },
        ],
      },
      {
        name: "Short with 10 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 10, encoding: "UTF8" },
        outputs: [
          {
            format: "HEX",
            rounds: 10,
            value: "4cb125e919d39ab283964e06ce58dd8923fa599046b533958c9353317ab368066b9902c2e1a9c9376d66f321fcc2c0a1",
          },
        ],
      },
      {
        name: "HMAC With Short Key",
        input: { format: "TEXT", value: "Sample message for keylen<blocklen" },
        hmacKey: {
          format: "HEX",
          value: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F",
        },
        outputs: [
          {
            format: "HEX",
            value: "d588a3c51f3f2d906e8298c1199aa8ff6296218127f6b38a90b6afe2c5617725bc99987f79b22a557b6520db710b7f42",
          },
        ],
      },
      {
        name: "HMAC With Medium Key",
        input: { format: "TEXT", value: "Sample message for keylen=blocklen" },

        hmacKey: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F6061626364656667",
        },
        outputs: [
          {
            format: "HEX",
            value: "a27d24b592e8c8cbf6d4ce6fc5bf62d8fc98bf2d486640d9eb8099e24047837f5f3bffbe92dcce90b4ed5b1e7e44fa90",
          },
        ],
      },
      {
        name: "HMAC With Long Key",
        input: { format: "TEXT", value: "Sample message for keylen>blocklen" },
        hmacKey: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F9091929394959697",
        },
        outputs: [
          {
            format: "HEX",
            value: "e5ae4c739f455279368ebf36d4f5354c95aa184c899d3870e460ebc288ef1f9470053f73f7c6da2a71bcaec38ce7d6ac",
          },
        ],
      },
    ],
    "SHA-512": [
      {
        name: "Short",
        input: { format: "TEXT", value: "abc", encoding: "UTF8" },
        outputs: [
          {
            format: "HEX",
            value:
              "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
          },
        ],
      },
      {
        name: "Medium",
        input: {
          format: "TEXT",
          value:
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
          encoding: "UTF8",
        },
        outputs: [
          {
            format: "HEX",
            value:
              "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
          },
        ],
      },
      {
        name: "Long",
        input: { format: "TEXT", value: millionaAscii, encoding: "UTF8" },
        outputs: [
          {
            format: "HEX",
            value:
              "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
          },
        ],
      },
      {
        name: "Short with 5 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 5, encoding: "UTF8" },
        outputs: [
          {
            format: "HEX",
            rounds: 5,
            value:
              "299b2e3ce932e4d0e9005345e37af5a4cc6be21e6b6e21231ce71ccde2a7aba4a6822cd7a9aaf9b13918db05ede70d3f1e6af65f8ad0bda1c4c4fa263e3cabdd",
          },
        ],
      },
      {
        name: "Short with 10 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 10, encoding: "UTF8" },
        outputs: [
          {
            format: "HEX",
            rounds: 10,
            value:
              "4c3ead8c83442fff47d4386702044f2a6c19730a806de541964b0fa9987cac08641611e02b2e0742ef2600ff82bfe3a711567c8e76dda16b4948f4c76e3c6e9c",
          },
        ],
      },
      {
        name: "HMAC With Short Key",
        input: { format: "TEXT", value: "Sample message for keylen<blocklen" },
        hmacKey: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        },
        outputs: [
          {
            format: "HEX",
            value:
              "fd44c18bda0bb0a6ce0e82b031bf2818f6539bd56ec00bdc10a8a2d730b3634de2545d639b0f2cf710d0692c72a1896f1f211c2b922d1a96c392e07e7ea9fedc",
          },
        ],
      },
      {
        name: "HMAC With Medium Key",
        input: { format: "TEXT", value: "Sample message for keylen=blocklen" },
        hmacKey: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
        },

        outputs: [
          {
            format: "HEX",
            value:
              "fc25e240658ca785b7a811a8d3f7b4ca48cfa26a8a366bf2cd1f836b05fcb024bd36853081811d6cea4216ebad79da1cfcb95ea4586b8a0ce356596a55fb1347",
          },
        ],
      },
      {
        name: "HMAC With Long Key",
        input: { format: "TEXT", value: "Sample message for keylen=blocklen" },
        hmacKey: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
        },
        outputs: [
          {
            format: "HEX",
            value:
              "d93ec8d2de1ad2a9957cb9b83f14e76ad6b5e0cce285079a127d3b14bccb7aa7286d4ac0d4ce64215f2bc9e6870b33d97438be4aaa20cda5c5a912b48b8e27f3",
          },
        ],
      },
    ],
    "SHA3-512": [
      {
        name: "Short",
        input: { format: "TEXT", value: "abc", encoding: "UTF8" },
        outputs: [
          {
            format: "HEX",
            value:
              "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
          },
        ],
      },
      {
        name: "Medium",
        input: {
          format: "TEXT",
          value:
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
          encoding: "UTF8",
        },
        outputs: [
          {
            format: "HEX",
            value:
              "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185",
          },
        ],
      },
      {
        name: "Long",
        input: { format: "TEXT", value: millionaAscii, encoding: "UTF8" },
        outputs: [
          {
            format: "HEX",
            value:
              "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87",
          },
        ],
      },
      {
        name: "Short with 5 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 5, encoding: "UTF8" },
        outputs: [
          {
            format: "HEX",
            rounds: 5,
            value:
              "8c74189ca608ad188bb96c8c374fb717ce982500dc2c0ce90ad8e5888b498ce9fda0e4bf256feeaaf1674b69e9ea80cf5ed444dfdd5d3eb05cfebd597b4aab67",
          },
        ],
      },
      {
        name: "Short with 10 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 10, encoding: "UTF8" },
        outputs: [
          {
            format: "HEX",
            rounds: 10,
            value:
              "0e3c0126a211563fdedc96149f1c2334aa5f5b2afcf5590cb71fec0ab348ba522e56c1136f165f525b22890e2546d2f9edbea6b6f5e929237b6c0f395e1b2e9b",
          },
        ],
      },
      {
        name: "HMAC With Short Key",
        input: { format: "TEXT", value: "Sample message for keylen<blocklen" },
        hmacKey: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        },
        outputs: [
          {
            format: "HEX",
            value:
              "4efd629d6c71bf86162658f29943b1c308ce27cdfa6db0d9c3ce81763f9cbce5f7ebe9868031db1a8f8eb7b6b95e5c5e3f657a8996c86a2f6527e307f0213196",
          },
        ],
      },
      {
        name: "HMAC With Medium Key",
        input: { format: "TEXT", value: "Sample message for keylen=blocklen" },
        hmacKey: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F4041424344454647",
        },
        outputs: [
          {
            format: "HEX",
            value:
              "544e257ea2a3e5ea19a590e6a24b724ce6327757723fe2751b75bf007d80f6b360744bf1b7a88ea585f9765b47911976d3191cf83c039f5ffab0d29cc9d9b6da",
          },
        ],
      },
      {
        name: "HMAC With Long Key",
        input: { format: "TEXT", value: "Sample message for keylen>blocklen" },
        hmacKey: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F8081828384858687",
        },
        outputs: [
          {
            format: "HEX",
            value:
              "5f464f5e5b7848e3885e49b2c385f0694985d0e38966242dc4a5fe3fea4b37d46b65ceced5dcf59438dd840bab22269f0ba7febdb9fcf74602a35666b2a32915",
          },
        ],
      },
    ],
    SHAKE128: [
      {
        name: "Short",
        input: { format: "TEXT", value: "abc", encoding: "UTF8" },
        outputs: [
          { format: "HEX", value: "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2c", outputLen: 248 },
          {
            format: "HEX",
            value:
              "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc844c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca5783",
            outputLen: 504,
          },
          {
            format: "HEX",
            value:
              "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc844c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca5783789a41f8611214ce612394df286a62d1a2252aa94db9c538956c717dc2bed4f232a0294c857c730aa16067ac1062f1201fb0d377cfb9cde4c63599b27f3462bba4a0ed296c801f9ff7f57302bb3076ee145f97a32ae68e76ab66c48d51675bd49acc29082f5647584e6aa01b3f5af057805f973ff8ecb8b226ac32ada6f01c1fcd4818cb006aa5b4cdb3611eb1e533c8964cacfdf31012cd3fb744d02225b988b475375faad996eb1b9176ecb0f8b2871723d6dbb804e23357e50732f5cfc904b1",
            outputLen: 2048,
          },
        ],
      },
      {
        name: "Medium",
        input: {
          format: "TEXT",
          value:
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
          encoding: "UTF8",
        },
        outputs: [
          { format: "HEX", value: "7b6df6ff181173b6d7898d7ff63fb07b7c237daf471a5ae5602adbccef9ccf", outputLen: 248 },
          {
            format: "HEX",
            value:
              "7b6df6ff181173b6d7898d7ff63fb07b7c237daf471a5ae5602adbccef9ccf4b37e06b4a3543164ffbe0d0557c02f9b25ad434005526d88ca04a6094b93ee5",
            outputLen: 504,
          },
          {
            format: "HEX",
            value:
              "7b6df6ff181173b6d7898d7ff63fb07b7c237daf471a5ae5602adbccef9ccf4b37e06b4a3543164ffbe0d0557c02f9b25ad434005526d88ca04a6094b93ee57a55d5ea66e744bd391f8f52baf4e031d9e60e5ca32a0ed162bb89fc908097984548796652952dd4737d2a234a401f4857f3d1866efa736fd6a8f7c0b5d02ab06e5f821b2cc8cb8b4606fb15b9527cce5c3ec02c65cd1cdb5c81bd67686ebdd3b5b3fcffb123ca8ca63df53537042f64637ab595f06e865ebaa322b253bfa533a056b46c7a63e21e569ff3cb26a976ccb749104adfce5f8db6751bbdbf0d898c22dad8e85523376744b889a7e68fab7e68699cd63bcc3d40e6b8cbb39e8e8a0931",
            outputLen: 2048,
          },
        ],
      },
      {
        name: "Long",
        input: { format: "TEXT", value: millionaAscii, encoding: "UTF8" },
        outputs: [
          { format: "HEX", value: "9d222c79c4ff9d092cf6ca86143aa411e369973808ef97093255826c5572ef", outputLen: 248 },
          {
            format: "HEX",
            value:
              "9d222c79c4ff9d092cf6ca86143aa411e369973808ef97093255826c5572ef58424c4b5c28475ffdcf981663867fec6321c1262e387bccf8ca676884c4a9d0",
            outputLen: 504,
          },
          {
            format: "HEX",
            value:
              "9d222c79c4ff9d092cf6ca86143aa411e369973808ef97093255826c5572ef58424c4b5c28475ffdcf981663867fec6321c1262e387bccf8ca676884c4a9d0c13bfa6869763d5ae4bbc9b3ccd09d1ca5ea7446538d69b3fb98c72b59a2b4817db5eadd9011f90fa71091931f8134f4f00b562e2fe105937270361c1909862ad45046e3932f5dd311ec72fec5f8fb8f60b45a3bee3f85bbf7fcedc6a555677648e0654b381941a86bd3e512657b0d57a7991fc4543f89d8290492222ce4a33e17602b3b99c009f7655f87535cdaa3716f58c47b8a157ad195f02809f27500b9254979311c6bb415968cd10431169a27d5a8d61e13a6b8b77af1f8b6dd2eefdea0",
            outputLen: 2048,
          },
        ],
      },
      {
        name: "Short with 5 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 5, encoding: "UTF8" },
        outputs: [
          {
            format: "HEX",
            rounds: 5,
            value: "99d5aa0763f5bd9464ed4bbc631ecdac6f67e77cbf61c7f7171dd2ffa892ba",
            outputLen: 248,
          },
        ],
      },
      {
        name: "Short with 10 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 10, encoding: "UTF8" },
        outputs: [
          {
            format: "HEX",
            rounds: 10,
            value: "5a5aeb2022e0e92ef4da3dc3e261a9303224b65cf6666f87a4d395a4ab94fe",
            outputLen: 248,
          },
        ],
      },
    ],
    SHAKE256: [
      {
        name: "Short",
        input: { format: "TEXT", value: "abc", encoding: "UTF8" },
        outputs: [
          { format: "HEX", value: "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b57", outputLen: 248 },
          {
            format: "HEX",
            value:
              "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751",
            outputLen: 504,
          },
          {
            format: "HEX",
            value:
              "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e41385141204f329979fd3047a13c5657724ada64d2470157b3cdc288620944d78dbcddbd912993f0913f164fb2ce95131a2d09a3e6d51cbfc622720d7a75c6334e8a2d7ec71a7cc29cf0ea610eeff1a588290a53000faa79932becec0bd3cd0b33a7e5d397fed1ada9442b99903f4dcfd8559ed3950faf40fe6f3b5d710ed3b677513771af6bfe11934817e8762d9896ba579d88d84ba7aa3cdc7055f6796f195bd9ae788f2f5bb96100d6bbaff7fbc6eea24d4449a2477d172a5507dcc931412",
            outputLen: 2048,
          },
        ],
      },
      {
        name: "Medium",
        input: {
          format: "TEXT",
          value:
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
          encoding: "UTF8",
        },
        outputs: [
          { format: "HEX", value: "98be04516c04cc73593fef3ed0352ea9f6443942d6950e29a372a681c3deaf", outputLen: 248 },
          {
            format: "HEX",
            value:
              "98be04516c04cc73593fef3ed0352ea9f6443942d6950e29a372a681c3deaf4535423709b02843948684e029010badcc0acd8303fc85fdad3eabf4f78cae16",
            outputLen: 504,
          },
          {
            format: "HEX",
            value:
              "98be04516c04cc73593fef3ed0352ea9f6443942d6950e29a372a681c3deaf4535423709b02843948684e029010badcc0acd8303fc85fdad3eabf4f78cae165635f57afd28810fc22abf63df55c5ead450fdfb64209010e982102aa0b5f0a4b4753b53eb4b5319c06986f5aac5cc247256d06b05a273d7ef8d31864777d488d541451ed82a38926582deb65d40ddb959b79dbe933635f9f3e2ae57f7c6aefc4d5bd7f230070fc2e9e2357d4eb39cee4bd064c4a33f35d5f652774fe941300cce4e800b127d54ba3548986db411d08dee19a295c1e9219e8c76a292bae5cfecf54785b37044bac9deef0f129c666b99719164d5f62ccef52b2ae53e4e8e971646",
            outputLen: 2048,
          },
        ],
      },
      {
        name: "Long",
        input: { format: "TEXT", value: millionaAscii, encoding: "UTF8" },
        outputs: [
          { format: "HEX", value: "3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234dfd1", outputLen: 248 },
          {
            format: "HEX",
            value:
              "3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234dfd13a3fd124d4df76c0a539ee7dd2f6e1ec346124c815d9410e145eb561bcd97b18",
            outputLen: 504,
          },
          {
            format: "HEX",
            value:
              "3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234dfd13a3fd124d4df76c0a539ee7dd2f6e1ec346124c815d9410e145eb561bcd97b18ab6ce8d5553e0eab3d1f7dfb8f9deefe16847e2192f6f61fb82fb90dde60b19063c56a4c55cdd7b672b75bf515adbfe204903c8c0036de54a2999a920de90f66d7ff6ec8e4c93d24ae346fdcb3a5a5bd5739ec15a6eddb5ce5b02da53039fac63e19555faa2eddc693b1f0c2a6fcbe7c0a0a091d0ee700d7322e4b0ff09590de166422f9ead5da4c993d605fe4d9c634843aa178b17672c6568c8a2e62abebea2c21c302bd366ad698959e1f6e434af155568b2734d8379fcd3ffe6489baffa6d7",
            outputLen: 2048,
          },
        ],
      },
      {
        name: "Short with 5 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 5, encoding: "UTF8" },
        outputs: [
          {
            format: "HEX",
            rounds: 5,
            value: "70368c73548e76dd6405ea6c1b4358eb0aeb4c0efe73526c7c6e1d9a9e4e0a",
            outputLen: 248,
          },
        ],
      },
      {
        name: "Short with 10 Rounds",
        input: { format: "TEXT", value: "abc", rounds: 10, encoding: "UTF8" },
        outputs: [
          {
            format: "HEX",
            rounds: 10,
            value: "d706c35b6642f39a27635c61c85ab13e76827de8fde4557e25bfc96b445f10",
            outputLen: 248,
          },
        ],
      },
    ],
    CSHAKE128: [
      {
        name: "Short Data",
        input: { format: "HEX", value: "00010203" },
        customization: { format: "TEXT", value: "Email Signature" },
        outputs: [
          { format: "HEX", value: "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5", outputLen: 256 },
        ],
      },
      {
        name: "Long Data",
        input: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
        },
        customization: { format: "TEXT", value: "Email Signature" },
        outputs: [
          { format: "HEX", value: "c5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b", outputLen: 256 },
        ],
      },
      {
        name: "Long Data With Long Customization",
        input: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
        },
        customization: {
          format: "TEXT",
          value:
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        },
        outputs: [
          { format: "HEX", value: "e4e44126332673143120f8f1d160ed103b43277787adf64fc5f86ed08f1e01dd", outputLen: 256 },
        ],
      },
    ],
    CSHAKE256: [
      {
        name: "Short Data",
        input: { format: "HEX", value: "00010203" },
        customization: { format: "TEXT", value: "Email Signature" },
        outputs: [
          {
            format: "HEX",
            value:
              "d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c",
            outputLen: 512,
          },
        ],
      },
      {
        name: "Long Data",
        input: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
        },
        customization: { format: "TEXT", value: "Email Signature" },
        outputs: [
          {
            format: "HEX",
            value:
              "07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac86430273091727f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb",
            outputLen: 512,
          },
        ],
      },
      {
        name: "Long Data With Long Customization",
        input: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
        },
        customization: {
          format: "TEXT",
          value:
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        },
        outputs: [
          {
            format: "HEX",
            value:
              "6c3bc0d35932de54311706668fea4a03d044b32ec2ed6cb525d625556c75b130a33d836630d62ac610c4e2c8753783bc5b1046cb95fac0377ec3ee06525651b8",
            outputLen: 512,
          },
        ],
      },
    ],
    KMAC128: [
      {
        name: "Short Data Without Customization",
        input: { format: "HEX", value: "00010203" },
        kmacKey: {
          format: "HEX",
          value: "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
        },
        outputs: [
          { format: "HEX", value: "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e", outputLen: 256 },
        ],
      },
      {
        name: "Short Data With Customization",
        input: { format: "HEX", value: "00010203" },
        customization: { format: "TEXT", value: "My Tagged Application" },
        kmacKey: {
          format: "HEX",
          value: "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
        },
        outputs: [
          { format: "HEX", value: "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5", outputLen: 256 },
        ],
      },
      {
        name: "Long Data With Long Customization",
        input: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
        },
        customization: {
          format: "TEXT",
          value:
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        },
        kmacKey: {
          format: "HEX",
          value: "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
        },
        outputs: [
          { format: "HEX", value: "308edaf1c4ffac004fdd62da5c52011159c0f45fb6cb564940d95bcec4b8e369", outputLen: 256 },
        ],
      },
      {
        name: "Long Data With Long Customization With Long Key",
        input: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
        },
        customization: {
          format: "TEXT",
          value:
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        },
        kmacKey: {
          format: "TEXT",
          value:
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        },
        outputs: [
          { format: "HEX", value: "9a045678281312a1ef3389b22bfcf2bfeb4c38d7c477b315eb3a2f3d929e0736", outputLen: 256 },
        ],
      },
      {
        name: "Long Data With Customization",
        input: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
        },
        customization: { format: "TEXT", value: "My Tagged Application" },
        kmacKey: {
          format: "HEX",
          value: "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
        },
        outputs: [
          { format: "HEX", value: "1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230", outputLen: 256 },
        ],
      },
    ],
    KMAC256: [
      {
        name: "Short Data With Customization",
        input: { format: "HEX", value: "00010203" },
        customization: { format: "TEXT", value: "My Tagged Application" },
        kmacKey: {
          format: "HEX",
          value: "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
        },
        outputs: [
          {
            format: "HEX",
            value:
              "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd",
            outputLen: 512,
          },
        ],
      },
      {
        name: "Long Data With Customization",
        input: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
        },
        customization: { format: "TEXT", value: "My Tagged Application" },
        kmacKey: {
          format: "HEX",
          value: "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
        },
        outputs: [
          {
            format: "HEX",
            value:
              "b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d970fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965",
            outputLen: 512,
          },
        ],
      },
      {
        name: "Long Data With Long Customization",
        input: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
        },
        customization: {
          format: "TEXT",
          value:
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        },
        kmacKey: {
          format: "HEX",
          value: "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
        },
        outputs: [
          {
            format: "HEX",
            value:
              "af4eaeb69f5fdf34e090baf6eaab1e3985f8bef02a77b94f60270e7fa6132ca8c899ad2c8e7a7680d9d197039c72ba640a20e5cce978365791502386cd7f13b8",
            outputLen: 512,
          },
        ],
      },
      {
        name: "Long Data With Long Customization With Long Key",
        input: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
        },
        customization: {
          format: "TEXT",
          value:
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        },
        kmacKey: {
          format: "TEXT",
          value:
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        },
        outputs: [
          {
            format: "HEX",
            value:
              "4c2cca887c7e632062a421c574f8b9cd26b55d1ede7747e7ebc4d0e32f4e5f06814e439a5c0fc26c9312b7e0e4185cd7aedf54292c79480ca854e61a48b72f3c",
            outputLen: 512,
          },
        ],
      },
      {
        name: "Long Data Without Customization",
        input: {
          format: "HEX",
          value:
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
        },
        kmacKey: {
          format: "HEX",
          value: "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
        },
        outputs: [
          {
            format: "HEX",
            value:
              "75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69",
            outputLen: 512,
          },
        ],
      },
    ],
  };

  return hash_data;
});
