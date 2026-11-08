#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "donkey/analysis/signature_gen.h"
#include "donkey/analysis/signatures.h"
#include "donkey/binary/image.h"

namespace {

std::string fixture(const std::string& name) {
  return std::string(DONKEY_FIXTURE_DIR) + "/" + name;
}

std::vector<std::byte> read_fixture(const std::string& name) {
  std::ifstream file(fixture(name), std::ios::binary);
  const std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  std::vector<std::byte> bytes(text.size());
  for (std::size_t i = 0; i < text.size(); ++i) {
    bytes[i] = static_cast<std::byte>(text[i]);
  }
  return bytes;
}

const donkey::Signature* signature_named(const donkey::SignatureGenResult& result,
                                         const std::string& name) {
  for (const donkey::Signature& signature : result.set.signatures) {
    if (signature.name == name) {
      return &signature;
    }
  }
  return nullptr;
}

donkey::SignatureGenOptions library_options() {
  donkey::SignatureGenOptions options;
  options.library = "sigfuncs";
  options.version = "1.0";
  options.license = "MIT";
  return options;
}

}  // namespace

// The fixture library is sig/gen/sigfuncs.c built with -ffunction-sections into an object and an
// archive (sig/gen/PROVENANCE.md). Its global functions are sig_add, sig_mul, sig_lookup and
// sig_call_external. sig_local is static, and sig_table is data: neither may be named.
TEST(SignatureGen, NamesTheGlobalFunctionsOfAnArchiveAndNoLocalOne) {
  const std::vector<std::byte> archive = read_fixture("sig/gen/libsigfuncs.a");
  auto generated = donkey::generate_signatures(archive, library_options());
  ASSERT_TRUE(generated.has_value()) << generated.diagnostic().code;
  const donkey::SignatureGenResult& result = generated.value();
  std::set<std::string> names;
  for (const donkey::Signature& signature : result.set.signatures) {
    names.insert(signature.name);
  }
  EXPECT_EQ(names,
            (std::set<std::string>{"sig_add", "sig_mul", "sig_lookup", "sig_call_external"}));
  EXPECT_EQ(result.functions, 4U);
  EXPECT_EQ(result.skipped, 0U);
  EXPECT_FALSE(result.partial);
  EXPECT_TRUE(result.notes.empty());
  EXPECT_EQ(result.set.library, "sigfuncs");
  EXPECT_EQ(result.set.version, "1.0");
  EXPECT_EQ(result.set.license, "MIT");
  EXPECT_EQ(result.set.architecture, "x86_64");
}

// The length of each signature is the symbol's size as the object file itself records it. The
// oracle is the loader's reading of the same object, which keeps every symbol's size.
TEST(SignatureGen, EachLengthIsTheSizeOfItsSymbolInTheObject) {
  const std::vector<std::byte> object = read_fixture("sig/gen/sigfuncs.o");
  auto generated = donkey::generate_signatures(object, library_options());
  ASSERT_TRUE(generated.has_value()) << generated.diagnostic().code;
  auto loaded = donkey::load_binary(fixture("sig/gen/sigfuncs.o"));
  ASSERT_TRUE(loaded.has_value());
  std::size_t checked = 0;
  for (const donkey::Symbol& symbol : loaded.value().image.symbols) {
    if (symbol.kind != donkey::SymbolKind::Function || !symbol.exported || symbol.size == 0) {
      continue;
    }
    const donkey::Signature* signature = signature_named(generated.value(), symbol.name);
    ASSERT_NE(signature, nullptr) << symbol.name;
    EXPECT_EQ(signature->length, symbol.size) << symbol.name;
    ++checked;
  }
  EXPECT_EQ(checked, 4U);
}

// The bytes a relocation patches are wildcards, at the offsets the object's relocations name
// (readelf -r sigfuncs.o): sig_call_external has its call displacement at 2, and sig_lookup has its
// call to the local helper at 7 and its table address at 14. A function with no relocations has
// none.
TEST(SignatureGen, RelocatedBytesBecomeWildcards) {
  const std::vector<std::byte> archive = read_fixture("sig/gen/libsigfuncs.a");
  auto generated = donkey::generate_signatures(archive, library_options());
  ASSERT_TRUE(generated.has_value());
  const donkey::Signature* call = signature_named(generated.value(), "sig_call_external");
  ASSERT_NE(call, nullptr);
  ASSERT_EQ(call->wildcards.size(), 1U);
  EXPECT_EQ(call->wildcards[0].offset, 2U);
  EXPECT_EQ(call->wildcards[0].length, 4U);

  const donkey::Signature* lookup = signature_named(generated.value(), "sig_lookup");
  ASSERT_NE(lookup, nullptr);
  ASSERT_EQ(lookup->wildcards.size(), 2U);
  EXPECT_EQ(lookup->wildcards[0].offset, 7U);
  EXPECT_EQ(lookup->wildcards[0].length, 4U);
  EXPECT_EQ(lookup->wildcards[1].offset, 14U);
  EXPECT_EQ(lookup->wildcards[1].length, 4U);

  const donkey::Signature* add = signature_named(generated.value(), "sig_add");
  ASSERT_NE(add, nullptr);
  EXPECT_TRUE(add->wildcards.empty());
}

TEST(SignatureGen, TheSetReadsBackInItsCanonicalForm) {
  const std::vector<std::byte> archive = read_fixture("sig/gen/libsigfuncs.a");
  auto generated = donkey::generate_signatures(archive, library_options());
  ASSERT_TRUE(generated.has_value());
  const std::string text = donkey::write_signature_set(generated.value().set);
  auto parsed = donkey::parse_signature_set(text);
  ASSERT_TRUE(parsed.has_value()) << parsed.diagnostic().code << ": "
                                  << parsed.diagnostic().message;
  EXPECT_EQ(donkey::write_signature_set(parsed.value()), text);
}

// The generated signatures name the functions of the program that links the library, and nothing
// else. The program's own functions (sig_external, _start) and its data are not named. The program
// is sig/gen/sig_static, linked with -nostdlib -ffunction-sections, so the linker has changed the
// call and address fields that the object's relocations describe.
TEST(SignatureGen, AMatchInTheLinkedProgramNamesTheLibraryFunctionsAndNoOther) {
  const std::vector<std::byte> archive = read_fixture("sig/gen/libsigfuncs.a");
  auto generated = donkey::generate_signatures(archive, library_options());
  ASSERT_TRUE(generated.has_value());
  auto program = donkey::load_binary(fixture("sig/gen/sig_static"));
  ASSERT_TRUE(program.has_value()) << program.diagnostic().code;

  std::vector<donkey::SignatureFunction> functions;
  for (const donkey::Symbol& symbol : program.value().image.symbols) {
    if (symbol.kind == donkey::SymbolKind::Function && symbol.size != 0) {
      functions.push_back(donkey::SignatureFunction{symbol.address, symbol.address + symbol.size});
    }
  }
  ASSERT_FALSE(functions.empty());
  auto matches = donkey::identify_functions(generated.value().set, program.value().image,
                                            program.value().data, functions, {});
  ASSERT_TRUE(matches.has_value()) << matches.diagnostic().code;

  std::map<std::uint64_t, std::string> named;
  for (const donkey::SignatureMatch& match : matches.value()) {
    EXPECT_FALSE(match.ambiguous) << match.address;
    if (!match.name.empty()) {
      named[match.address] = match.name;
    }
  }
  std::set<std::string> names;
  for (const auto& [address, name] : named) {
    names.insert(name);
  }
  EXPECT_EQ(names,
            (std::set<std::string>{"sig_add", "sig_mul", "sig_lookup", "sig_call_external"}));
  for (const donkey::Symbol& symbol : program.value().image.symbols) {
    if (symbol.name == "sig_external" || symbol.name == "_start") {
      EXPECT_EQ(named.count(symbol.address), 0U) << symbol.name;
    }
  }
}

TEST(SignatureGen, AFileThatIsNeitherAnObjectNorAnArchiveIsRefused) {
  const std::vector<std::byte> text = {std::byte{'h'}, std::byte{'e'}, std::byte{'l'},
                                       std::byte{'l'}, std::byte{'o'}, std::byte{'\n'},
                                       std::byte{'x'}, std::byte{'y'}, std::byte{'z'},
                                       std::byte{'!'}, std::byte{'!'}, std::byte{'!'}};
  auto refused = donkey::generate_signatures(text, library_options());
  ASSERT_FALSE(refused.has_value());
  EXPECT_EQ(refused.diagnostic().code, "sig.input");
}

TEST(SignatureGen, AnExecutableIsNotARelocatableObject) {
  const std::vector<std::byte> program = read_fixture("sig/gen/sig_static");
  auto refused = donkey::generate_signatures(program, library_options());
  ASSERT_FALSE(refused.has_value());
  EXPECT_EQ(refused.diagnostic().code, "sig.not_relocatable");
}

TEST(SignatureGen, AnObjectCutShortIsRefusedWithoutAPartialSet) {
  std::vector<std::byte> object = read_fixture("sig/gen/sigfuncs.o");
  object.resize(100);  // the section table lies beyond this
  auto refused = donkey::generate_signatures(object, library_options());
  ASSERT_FALSE(refused.has_value());
  EXPECT_EQ(refused.diagnostic().code, "sig.truncated");
}

TEST(SignatureGen, TheLibraryVersionAndLicenceAreRequired) {
  const std::vector<std::byte> archive = read_fixture("sig/gen/libsigfuncs.a");
  donkey::SignatureGenOptions options = library_options();
  options.license.clear();
  auto refused = donkey::generate_signatures(archive, options);
  ASSERT_FALSE(refused.has_value());
  EXPECT_EQ(refused.diagnostic().code, "sig.options");
}

// A relocation of a type the generator does not know has no width, so its function is not named
// and a note says why. The other functions are still named. The relocation is changed in a copy of
// the object: entry 0 of .rela.text.sig_call_external (at file offset 0x2f8) gets type 127.
TEST(SignatureGen, AFunctionWithAnUnknownRelocationIsSkippedWithANote) {
  std::vector<std::byte> object = read_fixture("sig/gen/sigfuncs.o");
  const std::size_t r_info = 0x2f8 + 8;
  ASSERT_LT(r_info + 4, object.size());
  object[r_info] = std::byte{127};
  object[r_info + 1] = std::byte{0};
  object[r_info + 2] = std::byte{0};
  object[r_info + 3] = std::byte{0};
  // The object is still an object: only one relocation type changed.
  auto generated = donkey::generate_signatures(object, library_options());
  ASSERT_TRUE(generated.has_value()) << generated.diagnostic().code;
  EXPECT_EQ(signature_named(generated.value(), "sig_call_external"), nullptr);
  EXPECT_NE(signature_named(generated.value(), "sig_add"), nullptr);
  EXPECT_NE(signature_named(generated.value(), "sig_lookup"), nullptr);
  EXPECT_EQ(generated.value().skipped, 1U);
  bool noted = false;
  for (const std::string& note : generated.value().notes) {
    noted = noted || (note.find("sig_call_external") != std::string::npos &&
                      note.find("does not know") != std::string::npos);
  }
  EXPECT_TRUE(noted);
}
