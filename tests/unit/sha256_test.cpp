#include "common/sha256.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

namespace utcp::app {
namespace {

// FIPS 180-4 examples (NIST CSRC "SHA256.pdf" example values, and the one
// million 'a' vector of FIPS 180-2 appendix B.3).
struct Vector {
  std::string message;
  const char* digest;
};

std::vector<Vector> vectors() {
  return {
      {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
      {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
      {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",  // 448 bits
       "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
      {std::string(1'000'000, 'a'),
       "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"},
  };
}

std::vector<Sha256::Impl> impls() {
  std::vector<Sha256::Impl> out{Sha256::Impl::portable};
  if (Sha256::shani_available()) {
    out.push_back(Sha256::Impl::shani);
  }
  return out;
}

std::string digest_of(Sha256& h) { return to_hex(h.finish()); }

TEST(Sha256, FipsVectorsInOneUpdate) {
  for (const Sha256::Impl impl : impls()) {
    for (const Vector& v : vectors()) {
      Sha256 h(impl);
      h.update(v.message);
      EXPECT_EQ(h.size(), v.message.size());
      EXPECT_EQ(digest_of(h), v.digest) << "impl " << int(impl) << " len " << v.message.size();
    }
  }
}

TEST(Sha256, StreamingInPiecesGivesTheSameDigest) {
  for (const Sha256::Impl impl : impls()) {
    for (const Vector& v : vectors()) {
      for (const std::size_t piece : {std::size_t{1}, std::size_t{63}, std::size_t{64}, std::size_t{65}}) {
        Sha256 h(impl);
        for (std::size_t off = 0; off < v.message.size(); off += piece) {
          h.update(std::string_view(v.message).substr(off, piece));
        }
        EXPECT_EQ(digest_of(h), v.digest) << "impl " << int(impl) << " piece " << piece;
      }
    }
  }
}

TEST(Sha256, ImplementationsAgreeOnEveryLengthUpTo300) {
  if (!Sha256::shani_available()) {
    GTEST_SKIP() << "no SHA-NI on this CPU";
  }
  std::string msg;
  for (std::size_t len = 0; len <= 300; ++len) {
    Sha256 a(Sha256::Impl::portable);
    Sha256 b(Sha256::Impl::shani);
    a.update(msg);
    b.update(msg);
    EXPECT_EQ(to_hex(a.finish()), to_hex(b.finish())) << len;
    msg += static_cast<char>((len * 131 + 7) & 0xff);
  }
}

// Known answers from Python's hashlib.sha256 for every length 0..130 of the
// pattern byte i = (i * 131 + 7) & 0xff. They cover the padding boundaries
// (55, 56 and 63, 64 mod 64: FIPS 180-4 §5.1.1 needs a second block when the
// 0x80 byte and the 8-byte length do not fit), which the FIPS vectors above
// do not, and an implementation is compared with an independent one, not
// only with itself.
const char* const pattern_digests[] = {
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  // 0
      "ca358758f6d27e6cf45272937977a748fd88391db679ceda7dc7bf1f005ee879",  // 1
      "4a80a67af76ac958d9b3b9af012f83a552196b0116e980d91a315c95e62f922f",  // 2
      "17aef23a39d753e713c203c152454d29fa8e39a98e83a69b39a5094dba9ae951",  // 3
      "2aad11f94736f39dd139082c65f4b03537584e4a49221847e098238ddc6d153f",  // 4
      "f74b1421379962a45534bfff59f3d39431e8b80cd08f00de2d5a252a87753da3",  // 5
      "262957a1ba4d188c93ee074331fcf808a10487c54254abc5d20f91b76b0491f3",  // 6
      "d68796b7712ef368707a713257728d066d10964d9ac113a284888979415d588a",  // 7
      "dcbc821bb9a36f997efeabf7764797402a041575c40539ea9d549503d3225409",  // 8
      "24a1108979c137efa170e71c7f5d843874c1d3b39f812100569f10b1996f62c1",  // 9
      "ba3f51c8b1198f14620114fe83ba0c6bea120a466cdf996ca3d872669e3c38ff",  // 10
      "2b7795f34bf1bcfdf09a01b7987ec208d0808a16e48ab0d0bdc881192ed71ca6",  // 11
      "f03c8fea15a29f08284a8e4140a01c17f86d08054ffd9509e16b13693cc42435",  // 12
      "16675837bad66e5d8be4c047faf87f8749978c17b1d04b977f87dddfd5bc2ff4",  // 13
      "221043803819aeb68b6dcff0adf31f5031581db65e621c130056c616dc342cf1",  // 14
      "c0121582635a552f8e60baab7923fe1fc270423aae80c3bca723cc76af593a89",  // 15
      "bf1bb93d74f56e14ad36b4e45c1a7c75a32d93df95150c3e280a45bc7623420c",  // 16
      "6cf6584e0380783b1420a41616c7802cbe7f6ae72ea91c00e52c530e7a243ca5",  // 17
      "812f635d36626ec8d6d51045d77f21f71c6410494795ab61fd8332f808eaa75c",  // 18
      "d6166ef39d724209d8c495698cbfafd61120b8fa5afe095311bd0021f18a4b10",  // 19
      "a83fae9a0c8247db228230415c33dac27608f9768cc63a09ce0b305e35f3fbd0",  // 20
      "54be4b03654a24a9a39a20382c24d7a0498385d0ebbc5bdc8c5cd75ecf823757",  // 21
      "0593518b5a52d7e01bab2c58d8011f25711bc5af69b152062917fc840438a46f",  // 22
      "0a0fe347b677937abbf6808fc12cd8bb163a2207459dc3a36d99b8bcf54d9832",  // 23
      "cd881948c51a6d9435b812ad00fb10e11b6f4ada57daaef4dc1cad1adf4d897d",  // 24
      "76c385562d302bc0f65e5fc042125ac546346fef3f0290e56e81e9dafd1a94bf",  // 25
      "10701c8195e71e13ba28c34b8c20cca04fd350ce3125b7f4a2956865ec30c35f",  // 26
      "e23c4022ad0e2e97798e808c5d1c5bc903fcb415acad11a524b8ef5decb2406c",  // 27
      "410652a8aa54d81da9d120be965cf682fab444e31209c606dbe18701fb7f7d7a",  // 28
      "842e8b2ec7692ad32049919363370075e3e4085e2ae15a136afd7ebade72b65e",  // 29
      "caae9a259763141f60e33b4d9eefb7064bf5295f6ea134ecd3cff8c75462ac79",  // 30
      "b40a28e1f3c2313f0c11d4cac74153540d766e4fca27dbbaedfbc2ea6c1e8d30",  // 31
      "bc9aa1b102854f1e4b21064c8d8552a658396222da87d1d75158f1fb15989168",  // 32
      "ba2525a86a58dca8882443e63aebb5cba28e46d3eac03ac86ada03154bf39d3f",  // 33
      "b7718965c30b9a89a2dddc0fcaeff52edb5bbbb34d3c453db8b7befdbb751215",  // 34
      "f8e4cbc4f4ddaf53ff80e4485a6cc72b8a9258abf244b6f2e96c65dd852f4a76",  // 35
      "f13407d53a6676b909893a22597b96de0fae3295419e788749cf0e076659b82e",  // 36
      "09475090c09806082901c22b941ee1ccf64bd34f3230ea1453ed81302060cc7f",  // 37
      "31d5d52d3e26ecc8d2b90bbaf3536cbee79834affc74c8cf1357cc4767699cbe",  // 38
      "6e37397e43bc3abd83af2354f800ef17f92cedf3458f53325c1e4ad05ab78c1f",  // 39
      "2c5acec66ef219b615930373916433c11a1366a8395be14b2412fa9150115b7f",  // 40
      "f2835d6b1ef8f3104fbbb6ec1863d5263ccdb35ad128139b8a4fcb0a14e92e0f",  // 41
      "710ac95780e9560bb84483fd03d2603c03ffee45887af2149f64fcd8e271a703",  // 42
      "98f0a3da85962fe089448268ca36758c43b95a836c8f6d392ce071e6cd8df294",  // 43
      "cb4fc478d9b0a365bd0d19f9d0bb74c79c080308c91c1d7d25610f101d1bce0d",  // 44
      "233115cff023a05c3c574f104422c3bacba633dafa7da71cf8395becbae2e244",  // 45
      "3ffcbbd46e00096b427006d71983dbd61906c9c33418f177c91ae102c7fed024",  // 46
      "b992da42a805995c855a4ecc0c7b4f4310d5972bae9edbf2e1f2b9ffd59a7707",  // 47
      "a76bcd9e614588d92f6ad18599cc025c2e21c38ed1127d040f83ca356af2edff",  // 48
      "00b9883f6ada7ba1adeff0517e20346fe50af9c4d19ace2aa85b8845cd44ab5c",  // 49
      "ac073bb0beaa6b285662307e4b566fad47e632fd792a38d193d9b60c2e5718c3",  // 50
      "dbd5fdcad0fcd29408694c8953410848336d4360f2b72c14a9ac628a154c0adc",  // 51
      "af0041f8a62ed1c34dfa9afd0a17aba5cb85d265d45cf02c006d2baab13b4365",  // 52
      "9b4563a486a65e769dcb192e0a6659b96ab2b7b6f52bf9091c5ecab75ad9fb9b",  // 53
      "df0dfd870292b2cb91ca3d2df4aeca24947f6ecc609d3bf6ed64dea8a4b5be69",  // 54
      "16ed9c4697ca11d5f6fb25ea7900252dd4cb97215d7f6d0b2bb3e2a86ac0ec72",  // 55
      "939ada93b2fe1e9c596d767bb408567c83e253667f0b25e5be8e16f35f2cbac9",  // 56
      "ab84281f3b181e6cfc7cf870c7f3e7912be6fd1ac49c7dd6b21f6c25bb9a5eaa",  // 57
      "46084278e607470669555dcbb4927df877d85663b0bed62ee31e769714a77d83",  // 58
      "dbdecd0cd48d8c3dffe97fec1eeec06dd10b4e0c8035cd82f40185aa2d142f83",  // 59
      "c8706e0b5979a41db9094a4a5ff1a19babbcdd4d1204c3e140981faeecc94cf8",  // 60
      "f8a1d57f033ce7e62290870f950025b3396c445c55542480d065f0554dc0eae2",  // 61
      "6e5dc5ee1806926ba4bb9f4fa79276a040a15ac10811b04d80e900741703c6d0",  // 62
      "6073f83b09ae82016cdbe24c18996c48f0eaa08ca675d0f6b90b807fc29e0149",  // 63
      "b337ba9b0c69c391364e985fdcb23a889887e59800832c92fbfa22b8a3c40304",  // 64
      "9d6a3fb113b586b4ab97bc11c993a27bd9b7bbcb756e0646083dc47a679600e6",  // 65
      "d513c6a4c03ac076f0d41c8645233e8ec97f7acf93bd442295f8e4c75c30fb25",  // 66
      "13001f3258b62efa5e2be644d50f970fdf99f466466cae528ff083054db7f841",  // 67
      "1653e30a34fa1f2ef632b4c0594e94e696d6e2b0238d498a40df65808b9a7eab",  // 68
      "8fd85efca33abf0dc54f345264eba2fc5fb394872683ccc032f8021a5003e5fd",  // 69
      "fb4dfe5aa11a50089cba1b05012caf00a279bd22a22dd00caf9effb0863af68e",  // 70
      "b08e101e14abd95b007067e8bf9f2d6d7d83ebb306622030d25b8f02a6c63693",  // 71
      "f60e389e54f243fc70bb7ed4e44ca3dc0c5efe4a9ff2385acf7d2120c0a1a665",  // 72
      "ab10ab1b874f13075f84de4103f511f41efbec4167808730045fe0202c0f1c2e",  // 73
      "6bf852344056dd97e8ee17f1ade242dac88784b68e13b5a6021e2509295b991d",  // 74
      "ad143df0ba4a75f46a89da6323856c67af23fd9ec2314968cf3be98c42f86746",  // 75
      "d315356b49ec9276e55a446adaa841bc604fc0f3432e0e93f75fb9fa1afc3120",  // 76
      "5242db27385fbbcd1d2c4ec281b63758943007aff7f5f92d18640796fb160ea9",  // 77
      "d6da5bfa422e5018ec7bdc39b48300d1caaa3c6210ee6a940c16734ccc712117",  // 78
      "2f391ed6b4588fdddabf2afb4c4054772fc3a6878e11cc9974751aded82f818b",  // 79
      "6e0f69d1b09fa647e8b20465b8dde48d5fbe82b14b4dfc3f4b6b17fd9864f4ce",  // 80
      "8385326634cd6f2ade82b191066528f70f45f0d5e0b8c5c7f5a407016e6a07ac",  // 81
      "64e480b23f0457cc09c6045863fa99c5e5172c674380ad5c8f518a5b94ff1d4c",  // 82
      "b822feeb116a5bfd1f761873855914a597f483ef939dcae7eeedbad202ac687a",  // 83
      "1ae56af10af1fdc3bca6769f000d9d4af5c5c615a249dfb2e48e4f1f93919be9",  // 84
      "352734af26b50ecec375a1a7a72aa250029aeecff4314b67f850acbb35f2372f",  // 85
      "bbeffc3a45b381e4a1b497f8c51235590bad88859769b336f7daeeaa5e406d82",  // 86
      "f2ef14fd73b48e7fa3b0c4b38a91b2631c499956659e99ab564ebe54ef84b0c9",  // 87
      "a6d19b9afd91c15a699d0a368449a222e492f8e809773752789bbbf5a4eb8dcb",  // 88
      "57218865054203a355da67036a26688e29d77e52a88325a71e11a7ead40da4bc",  // 89
      "1f5d4b9d3add403f735f748a26d5cd1bba262958a1cbeda293f29866db63758a",  // 90
      "e8899b7a1b92bddae077eec05805dd6e9a3698d73583c036ccc5ce5cb9e77c31",  // 91
      "db2735d8eec96eb180aaa217336f765b201193503244e08dcc5538ef81577ebf",  // 92
      "d23235f2dddd1b2f8833cc1922778dfc9df816a0d687ffa6bf472e1d56334bf1",  // 93
      "66508e4b92f8f3f5c1fe5cdbe73bb87c2170ec6ef0ab948545f6ccee9dfc24ec",  // 94
      "c8736de66d8bf2834a0eddb432eca75a8b84ea1c82b9b3b7291374471700789b",  // 95
      "6e6968bd9fcbe5dc5fab9a474b353fe87360b86943a867b4907630eadbb5cd80",  // 96
      "1ecd026221adf1ab2f8b2ee70743497cea0d4a2421962f4719ed1b38448bfc80",  // 97
      "62efc30d8ffab16f81842a105bafdc9e3371bc2b0af6c840ee27a9cd4dc7ec37",  // 98
      "d3d387c7f04cfa925f04c1a81cd26c41c5331d79f6bead38497347214167d6dd",  // 99
      "b493defffa04821dbe4b757ed039293591680fd3f05a08182b145193205fcba0",  // 100
      "83315009356e1b4f0ac57dc8af20c6777f5d98d275e2a2e230322e4bb1cb0a18",  // 101
      "5496a287a2be3938d7ece0db6e32d32e31b602645a9d832846484831a49c4f38",  // 102
      "a072681dbd185cead5c938d152d231cdabbd85408831eadeb41570b9fe02b73d",  // 103
      "4814f8d16ef045a193077ba4452f3919bba92334096e984e7daf0ae95567b4b9",  // 104
      "5acaf83c0edbd903d6b08753c25f817892bbba274c7524ddd11d84654a448a95",  // 105
      "fec5d243c0af8edaec8e4ae97751123635554225ee89d90364647275fe5edbaf",  // 106
      "e5870bb50411c36c5815e806e9bf76019d9bcb64b171e1a720952830c91a7e2b",  // 107
      "dad0513def7ae493a4f5d2f370cc66f749dd0f42847f2090a8f66079beab3777",  // 108
      "16280aa64c0452058e623a0a2c3a34e9f45d4fc5ce9cfd3c8d47f5c54c5c3cd5",  // 109
      "35a67e9d58774a1c46f485068891200debdadba4283ebb368c01ddfb2157d454",  // 110
      "2d9743c1caad343dbb42d591b307dcad9879a9568fa2adf98894dbb62b4a096a",  // 111
      "ecf2bd67b292d09ff421b2f279b9f9525c17b8bbd71711dba7fae1fab799c791",  // 112
      "c7257986b43b9cd02b4083cd2749e26446d183207e5799ece7e474bc69239100",  // 113
      "cc0a4e02c4e4804411cc269de174aed03b12a3897d9181b227cdfaa838b19a9d",  // 114
      "cd11c192e356e941ba1c8401c6e1e3584b801363ab871239a0b59e7f73ddae14",  // 115
      "83602167bc0fd4689ebba2e3e1a103b71b899b556ebdefc0ef27970a23143724",  // 116
      "73f060cd9120df8516941d4725bcfb0003f79a4d380d573e89609607f14927f1",  // 117
      "3aff8a915add96fd9b2b7a060069d97a65145dad43f199092ec3b7fde41772ca",  // 118
      "9773fbac8194c3d789af101b49b6a26073076895ef6e0f658432849dd477a43f",  // 119
      "070a538f085dd94821d4dc197c5c8b791051891d4fa2a1bf25d3c275236676f7",  // 120
      "05a3caed94d5ee13402c4422abc9fa3ab0dbda743a8480a12cafefe5e5da992c",  // 121
      "7dbb18dee0eb18da9eb73bea2044dca700eeb54302a539ba77c8fade73230c22",  // 122
      "27f27eb488368deb9c8ff2eacc8ce92253aa52d87ef3f22e696134f20dd3c3d6",  // 123
      "9210d7a78f0034aca43b3eed23b133adf55d68e494c5a7d6bcfd60e37ad4dcce",  // 124
      "1efb8d002b76d2a184f6474143648e3d22e80f4078b4fc265cad47ff713a39e8",  // 125
      "432d4ce0fcae1665f79a402d68fe0a88e7053cd2686b92624bc9e993eff99d8d",  // 126
      "5072b7a9a4cda7f6d80f1eff09b8b9653201dba22319daf32c6c05339d57f483",  // 127
      "485a94e53eba9717a5d8b7b4489cad92a752f1c5722e7dfd29dd164b7c438d11",  // 128
      "72b63785704123441e7405a2620b859d1f107604ef5882e2674e82cc40d173a6",  // 129
      "21c10b3ba180b93247fab48bd9318b4cb8089e313676ce507c18710864e57e8f",  // 130
};

TEST(Sha256, KnownAnswersForEveryLengthUpTo130) {
  std::string msg;
  for (std::size_t len = 0; len < std::size(pattern_digests); ++len) {
    for (const Sha256::Impl impl : impls()) {
      Sha256 one(impl);
      one.update(msg);
      EXPECT_EQ(digest_of(one), pattern_digests[len]) << "impl " << int(impl) << " len " << len;
      Sha256 bytewise(impl);
      for (const char c : msg) {
        bytewise.update(std::string_view(&c, 1));
      }
      EXPECT_EQ(digest_of(bytewise), pattern_digests[len]) << "impl " << int(impl) << " len " << len;
    }
    msg += static_cast<char>((len * 131 + 7) & 0xff);
  }
}

TEST(Sha256, FinishStartsANewMessage) {
  Sha256 h;
  h.update("garbage");
  (void)h.finish();
  EXPECT_EQ(h.size(), 0u);
  h.update("abc");
  EXPECT_EQ(digest_of(h), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Sha256, HexHelpers) {
  EXPECT_EQ(sha256_hex(std::string_view("abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  const std::uint8_t b[] = {0x00, 0x0f, 0xa5, 0xff};
  EXPECT_EQ(to_hex(b), "000fa5ff");
}

}  // namespace
}  // namespace utcp::app
