#include <gtest/gtest.h>

#include <cstdint>
#include <iterator>
#include <limits>
#include <string>

#include "donkey/core/checked.h"
#include "donkey/core/ids.h"
#include "donkey/core/result.h"
#include "donkey/core/status.h"
#include "donkey/core/version.h"

namespace {

using donkey::Diagnostic;
using donkey::Result;
using donkey::Status;
using donkey::VoidResult;

TEST(Status, NamesAreStableAndDistinct) {
  const Status all[] = {
      Status::Success,          Status::Partial,        Status::Unsupported,
      Status::InvalidInput,     Status::ResourceLimit,  Status::Cancelled,
      Status::PermissionDenied, Status::CorruptProject, Status::InternalError,
  };
  for (std::size_t i = 0; i < std::size(all); ++i) {
    ASSERT_NE(donkey::status_name(all[i]), nullptr);
    for (std::size_t j = i + 1; j < std::size(all); ++j) {
      EXPECT_STRNE(donkey::status_name(all[i]), donkey::status_name(all[j]));
    }
  }
  EXPECT_STREQ(donkey::status_name(Status::Success), "Success");
}

TEST(Diagnostic, CarriesCodeMessageAndOffset) {
  const auto diagnostic =
      Diagnostic::make(Status::InvalidInput, "elf.bad_magic", "not an ELF file", 0);
  EXPECT_EQ(diagnostic.status, Status::InvalidInput);
  EXPECT_EQ(diagnostic.code, "elf.bad_magic");
  EXPECT_EQ(diagnostic.message, "not an ELF file");
  ASSERT_TRUE(diagnostic.offset.has_value());
  EXPECT_EQ(*diagnostic.offset, 0U);
}

TEST(Result, HoldsValueOrDiagnostic) {
  Result<int> value = 42;
  ASSERT_TRUE(value.has_value());
  EXPECT_EQ(value.value(), 42);
  EXPECT_EQ(value.status(), Status::Success);

  Result<int> error =
      donkey::make_error<int>(Status::Unsupported, "test.unsupported", "not supported here");
  ASSERT_FALSE(error.has_value());
  EXPECT_EQ(error.diagnostic().status, Status::Unsupported);
  EXPECT_EQ(error.diagnostic().code, "test.unsupported");
  EXPECT_EQ(error.status(), Status::Unsupported);
  EXPECT_THROW(static_cast<void>(error.value()), std::logic_error);
}

TEST(Result, SuccessDiagnosticIsRejected) {
  Result<int> invalid(Diagnostic::make(Status::Success, "", "impossible"));
  ASSERT_FALSE(invalid.has_value());
  EXPECT_EQ(invalid.diagnostic().status, Status::InternalError);
  EXPECT_EQ(invalid.diagnostic().code, "result.invalid_success_diagnostic");
}

TEST(ResultVoid, DefaultIsSuccessAndDiagnosticIsError) {
  VoidResult ok;
  EXPECT_TRUE(ok.has_value());
  EXPECT_EQ(ok.status(), Status::Success);

  VoidResult failed = donkey::make_void_error(Status::ResourceLimit, "test.limit", "too big");
  EXPECT_FALSE(failed.has_value());
  EXPECT_EQ(failed.status(), Status::ResourceLimit);
  EXPECT_EQ(failed.diagnostic().code, "test.limit");
}

TEST(Checked, AdditionDetectsOverflow) {
  std::uint64_t out = 0;
  EXPECT_FALSE(donkey::checked::add_overflow(1, 2, out));
  EXPECT_EQ(out, 3U);

  EXPECT_FALSE(
      donkey::checked::add_overflow(std::numeric_limits<std::uint64_t>::max() - 1, 1, out));
  EXPECT_EQ(out, std::numeric_limits<std::uint64_t>::max());

  out = 777;
  EXPECT_TRUE(donkey::checked::add_overflow(std::numeric_limits<std::uint64_t>::max(), 1, out));
  EXPECT_EQ(out, 777U);

  ASSERT_TRUE(donkey::checked::add(10, 20).has_value());
  EXPECT_EQ(donkey::checked::add(10, 20).value(), 30U);
  EXPECT_FALSE(donkey::checked::add(std::numeric_limits<std::uint64_t>::max(), 1).has_value());
}

TEST(Checked, SubtractionDetectsUnderflow) {
  std::uint64_t out = 0;
  EXPECT_FALSE(donkey::checked::sub_overflow(5, 3, out));
  EXPECT_EQ(out, 2U);

  out = 99;
  EXPECT_TRUE(donkey::checked::sub_overflow(3, 5, out));
  EXPECT_EQ(out, 99U);
}

TEST(Checked, MultiplicationDetectsOverflow) {
  std::uint64_t out = 0;
  EXPECT_FALSE(donkey::checked::mul_overflow(6, 7, out));
  EXPECT_EQ(out, 42U);

  out = 5;
  EXPECT_TRUE(donkey::checked::mul_overflow(1ULL << 32, 1ULL << 32, out));
  EXPECT_EQ(out, 5U);

  EXPECT_FALSE(donkey::checked::mul_overflow(0, std::numeric_limits<std::uint64_t>::max(), out));
  EXPECT_EQ(out, 0U);
}

TEST(Checked, AlignUpHandlesBoundaries) {
  std::uint64_t out = 0;
  EXPECT_TRUE(donkey::checked::align_up(0, 16, out));
  EXPECT_EQ(out, 0U);
  EXPECT_TRUE(donkey::checked::align_up(1, 16, out));
  EXPECT_EQ(out, 16U);
  EXPECT_TRUE(donkey::checked::align_up(16, 16, out));
  EXPECT_EQ(out, 16U);
  EXPECT_TRUE(donkey::checked::align_up(17, 16, out));
  EXPECT_EQ(out, 32U);
  EXPECT_FALSE(donkey::checked::align_up(1, 0, out));

  const auto maximum = std::numeric_limits<std::uint64_t>::max();
  EXPECT_FALSE(donkey::checked::align_up(maximum, 16, out));
  // Largest aligned value that fits still succeeds.
  EXPECT_TRUE(donkey::checked::align_up(maximum - 15, 16, out));
  EXPECT_EQ(out, maximum - 15);
}

TEST(Checked, RangeRejectsEveryOutOfBoundsCombination) {
  EXPECT_TRUE(donkey::checked::in_range(0, 0, 0));
  EXPECT_TRUE(donkey::checked::in_range(0, 10, 10));
  EXPECT_FALSE(donkey::checked::in_range(1, 10, 10));
  EXPECT_FALSE(donkey::checked::in_range(10, 1, 10));
  EXPECT_TRUE(donkey::checked::in_range(9, 1, 10));
  EXPECT_FALSE(donkey::checked::in_range(0, 11, 10));

  // Exhaustive small-domain property check.
  for (std::uint64_t offset = 0; offset <= 12; ++offset) {
    for (std::uint64_t length = 0; length <= 12; ++length) {
      for (std::uint64_t limit = 0; limit <= 12; ++limit) {
        const bool expected = offset + length <= limit;
        EXPECT_EQ(donkey::checked::in_range(offset, length, limit), expected)
            << "offset=" << offset << " length=" << length << " limit=" << limit;
      }
    }
  }
}

TEST(Ids, AreTypedAndStable) {
  const donkey::ImageId image(7);
  const donkey::FunctionId function(7);
  EXPECT_EQ(image.value(), function.value());
  EXPECT_TRUE(image.valid());
  EXPECT_FALSE(donkey::ImageId{}.valid());

  const donkey::Location location{image, donkey::AddressSpace::ImageRva, 0x401000};
  EXPECT_EQ(location.space, donkey::AddressSpace::ImageRva);
  EXPECT_EQ(std::hash<donkey::Location>{}(location), std::hash<donkey::Location>{}(location));
  EXPECT_STREQ(donkey::address_space_name(donkey::AddressSpace::FileOffset), "file_offset");
}

TEST(Version, MatchesProjectVersion) {
  EXPECT_EQ(donkey::version(), "0.1.0");
}

}  // namespace
