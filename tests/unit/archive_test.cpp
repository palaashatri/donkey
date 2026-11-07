#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "donkey/binary/archive.h"

namespace {

std::string padded(const std::string& text, std::size_t width) {
  std::string field = text;
  field.resize(width, ' ');
  return field;
}

/// One 60-byte member header. The size field is the size of the data written after it.
std::string header(const std::string& name, std::uint64_t size, const std::string& date = "0",
                   const std::string& mode = "100644") {
  std::string text;
  text += padded(name, 16);
  text += padded(date, 12);
  text += padded("0", 6);
  text += padded("0", 6);
  text += padded(mode, 8);
  text += padded(std::to_string(size), 10);
  text += "`\n";
  return text;
}

/// A member: its header and data, with the padding that makes the data even-length.
std::string member(const std::string& name, const std::string& data) {
  std::string text = header(name, data.size()) + data;
  if (data.size() % 2 != 0) {
    text += '\n';
  }
  return text;
}

std::string archive_of(const std::vector<std::string>& members) {
  std::string text = "!<arch>\n";
  for (const std::string& piece : members) {
    text += piece;
  }
  return text;
}

std::span<const std::byte> bytes_of(const std::string& text) {
  return std::span<const std::byte>(reinterpret_cast<const std::byte*>(text.data()), text.size());
}

std::string data_at(const std::string& archive, const donkey::ArchiveMember& member) {
  return archive.substr(static_cast<std::size_t>(member.offset),
                        static_cast<std::size_t>(member.size));
}

}  // namespace

TEST(Archive, ListsSystemVAndGnuNamesAndResolvesLongNames) {
  // A symbol table, the long-name table, a member whose name is a table reference, and
  // a short name with a trailing slash.
  const std::string long_names = "averyveryverylongobjectname.o/\n";
  const std::string text = archive_of({
      member("/", std::string(4, '\0')),
      member("//", long_names),
      member("/0", "obj"),
      member("short.o/", "x"),
  });
  const auto index = donkey::read_archive(bytes_of(text));
  ASSERT_TRUE(index.has_value()) << index.diagnostic().message;
  EXPECT_FALSE(index.value().partial) << index.value().note;
  ASSERT_EQ(index.value().members.size(), 4U);

  const auto& members = index.value().members;
  EXPECT_EQ(members[0].kind, donkey::ArchiveMemberKind::SymbolTable);
  EXPECT_EQ(members[1].kind, donkey::ArchiveMemberKind::LongNames);
  EXPECT_EQ(members[2].name, "averyveryverylongobjectname.o");
  EXPECT_EQ(members[2].kind, donkey::ArchiveMemberKind::Object);
  EXPECT_EQ(data_at(text, members[2]), "obj");
  EXPECT_EQ(members[3].name, "short.o");
  EXPECT_EQ(data_at(text, members[3]), "x");
}

TEST(Archive, ReadsBsdNamesFromTheStartOfTheMemberData) {
  // "#1/12": the first 12 bytes of the data are the name, which is included in the size.
  const std::string text = archive_of({
      header("#1/12", 12 + 5) + "bsd_object.o" + "hello" + "\n",
  });
  const auto index = donkey::read_archive(bytes_of(text));
  ASSERT_TRUE(index.has_value()) << index.diagnostic().message;
  ASSERT_EQ(index.value().members.size(), 1U);
  const auto& member_entry = index.value().members.front();
  EXPECT_EQ(member_entry.name, "bsd_object.o");
  EXPECT_EQ(member_entry.size, 5U);
  EXPECT_EQ(data_at(text, member_entry), "hello");
}

TEST(Archive, PaddingKeepsTheNextHeaderAligned) {
  // An odd-length member is followed by a pad byte; the next header must still be found.
  const std::string text = archive_of({member("odd.o/", "abc"), member("next.o/", "de")});
  const auto index = donkey::read_archive(bytes_of(text));
  ASSERT_TRUE(index.has_value()) << index.diagnostic().message;
  ASSERT_EQ(index.value().members.size(), 2U);
  EXPECT_EQ(index.value().members[0].name, "odd.o");
  EXPECT_EQ(index.value().members[1].name, "next.o");
  EXPECT_EQ(data_at(text, index.value().members[1]), "de");
}

TEST(Archive, ReadsDateAndModeAndTreatsBlankFieldsAsZero) {
  const std::string text = archive_of({
      header("a.o/", 1, "1700000000", "100755") + "x" + "\n",
      header("b.o/", 1, "", "") + "y" + "\n",
  });
  const auto index = donkey::read_archive(bytes_of(text));
  ASSERT_TRUE(index.has_value()) << index.diagnostic().message;
  ASSERT_EQ(index.value().members.size(), 2U);
  EXPECT_EQ(index.value().members[0].modified, 1700000000U);
  EXPECT_EQ(index.value().members[0].mode, 0100755U);
  EXPECT_EQ(index.value().members[1].modified, 0U);
  EXPECT_EQ(index.value().members[1].mode, 0U);
}

TEST(Archive, EmptyArchiveHasNoMembers) {
  const auto index = donkey::read_archive(bytes_of("!<arch>\n"));
  ASSERT_TRUE(index.has_value()) << index.diagnostic().message;
  EXPECT_TRUE(index.value().members.empty());
  EXPECT_FALSE(index.value().partial);
}

TEST(Archive, RefusesAFileThatIsNotAnArchive) {
  const auto index = donkey::read_archive(bytes_of("not an archive at all"));
  ASSERT_FALSE(index.has_value());
  EXPECT_EQ(index.diagnostic().code, "archive.bad_magic");
}

TEST(Archive, KeepsTheMembersBeforeATruncatedHeader) {
  const std::string text = archive_of({member("first.o/", "1")}) + "garbage!!";
  const auto index = donkey::read_archive(bytes_of(text));
  ASSERT_TRUE(index.has_value()) << index.diagnostic().message;
  EXPECT_TRUE(index.value().partial);
  EXPECT_NE(index.value().note.find("truncated"), std::string::npos) << index.value().note;
  ASSERT_EQ(index.value().members.size(), 1U);
  EXPECT_EQ(index.value().members.front().name, "first.o");
}

TEST(Archive, StopsAtAMemberThatRunsPastTheEnd) {
  // The header claims 100 bytes of data; only 3 follow.
  const std::string text = archive_of({member("ok.o/", "1"), header("big.o/", 100) + "abc"});
  const auto index = donkey::read_archive(bytes_of(text));
  ASSERT_TRUE(index.has_value()) << index.diagnostic().message;
  EXPECT_TRUE(index.value().partial);
  EXPECT_NE(index.value().note.find("past the end"), std::string::npos) << index.value().note;
  EXPECT_EQ(index.value().members.size(), 1U);
}

TEST(Archive, RejectsAHeaderWithoutItsTerminator) {
  std::string bad = header("bad.o/", 1) + "x" + "\n";
  bad[58] = 'X';  // the terminator is "`\n"
  const auto index = donkey::read_archive(bytes_of(archive_of({bad})));
  ASSERT_TRUE(index.has_value()) << index.diagnostic().message;
  EXPECT_TRUE(index.value().partial);
  EXPECT_TRUE(index.value().members.empty());
}

TEST(Archive, MemberLimitIsEnforced) {
  const std::string text = archive_of({member("a.o/", "1"), member("b.o/", "2")});
  donkey::ArchiveOptions options;
  options.max_members = 1;
  const auto index = donkey::read_archive(bytes_of(text), options);
  ASSERT_TRUE(index.has_value()) << index.diagnostic().message;
  EXPECT_TRUE(index.value().partial);
  EXPECT_EQ(index.value().members.size(), 1U);
  EXPECT_NE(index.value().note.find("member limit"), std::string::npos) << index.value().note;
}

TEST(Archive, NamesAreSanitized) {
  // A control byte in a name must not reach the output as a control byte.
  std::string name = "bad";
  name += '\x01';
  name += "name.o/";
  const auto index = donkey::read_archive(bytes_of(archive_of({member(name, "z")})));
  ASSERT_TRUE(index.has_value()) << index.diagnostic().message;
  ASSERT_EQ(index.value().members.size(), 1U);
  for (const char c : index.value().members.front().name) {
    EXPECT_GE(static_cast<unsigned char>(c), 0x20U);
  }
}
