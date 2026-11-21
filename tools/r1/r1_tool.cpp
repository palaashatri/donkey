// donkey-r1 (G20-T2): the R1 measurement.
//
//   donkey-r1 measure <work-dir> <decompile-dir> <result.json> <table.md>
//
// <work-dir> is the R1_WORK of tools/r1/build.cmake: it holds binaries.json and out/. For each
// binary B listed there, <decompile-dir>/B.json is the output of
// `donkey-cli decompile out/B --json --no-pseudocode --max-functions 1000000`; a missing or
// unreadable output is that binary's error. The result lists, per binary, the functions by status,
// the reasons of the Partial ones, and for a stripped binary the starts found against the function
// symbols of its unstripped twin. The exit status is 0 when every binary was measured, 2 when one
// or more had an error (both outputs are written either way), and 1 when the tool could not run.

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "donkey/binary/image.h"
#include "r1_measure.h"

namespace {

namespace fs = std::filesystem;
using donkey::r1::Binary;
using donkey::r1::Measure;
using donkey::r1::StartsComparison;

bool read_file(const fs::path& path, std::string& out) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return false;
  }
  std::ostringstream buffer;
  buffer << in.rdbuf();
  out = buffer.str();
  return static_cast<bool>(in) || in.eof();
}

bool write_file(const fs::path& path, const std::string& text) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out << text;
  // Closing flushes the buffer; a write that fails there must fail the run too.
  out.close();
  return !out.fail();
}

std::string quote(const std::string& text) {
  std::string out = "\"";
  for (const char c : text) {
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char escaped[8];
          std::snprintf(escaped, sizeof escaped, "\\u%04x", static_cast<unsigned>(c));
          out += escaped;
        } else {
          out += c;
        }
    }
  }
  return out + "\"";
}

/// The (count, note) pairs of `counts`, most frequent first, then by note.
std::vector<std::pair<std::size_t, std::string>> ranked(
    const std::map<std::string, std::size_t>& counts) {
  std::vector<std::pair<std::size_t, std::string>> out;
  for (const auto& [note, count] : counts) {
    out.emplace_back(count, note);
  }
  std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
    return a.first != b.first ? a.first > b.first : a.second < b.second;
  });
  return out;
}

std::string notes_json(const std::map<std::string, std::size_t>& counts) {
  std::string out = "[";
  bool first = true;
  for (const auto& [count, note] : ranked(counts)) {
    out += (first ? "" : ", ") + std::string("{\"note\": ") + quote(note) +
           ", \"functions\": " + std::to_string(count) + "}";
    first = false;
  }
  return out + "]";
}

std::string string_array(const std::vector<std::string>& items) {
  std::string out = "[";
  for (std::size_t i = 0; i < items.size(); ++i) {
    out += (i == 0 ? "" : ", ") + quote(items[i]);
  }
  return out + "]";
}

std::string table_cell(const std::string& text) {
  std::string out;
  for (const char c : text) {
    out += c == '|' ? std::string("\\|") : std::string(1, c);
  }
  return out;
}

int measure(const fs::path& work, const fs::path& decompiled, const fs::path& result_path,
            const fs::path& table_path) {
  std::string binaries_text;
  if (!read_file(work / "binaries.json", binaries_text)) {
    std::fprintf(stderr, "donkey-r1: cannot read %s\n", (work / "binaries.json").string().c_str());
    return 1;
  }
  auto binaries = donkey::r1::read_binaries(binaries_text);
  if (!binaries) {
    std::fprintf(stderr, "donkey-r1: %s\n", binaries.diagnostic().message.c_str());
    return 1;
  }

  std::string entries;
  std::string rows;
  std::map<std::string, std::size_t> first_notes;  // over the unstripped binaries
  std::size_t errors = 0;
  std::size_t total_functions = 0;
  std::size_t total_complete = 0;
  std::size_t total_unexplained = 0;
  for (const Binary& binary : binaries.value()) {
    Measure measured;
    measured.file = binary.file;
    std::string decompile_text;
    if (!read_file(decompiled / (binary.file + ".json"), decompile_text)) {
      measured.error = true;
      measured.error_reason = "no decompile output (the run failed or timed out)";
    } else if (auto counted = donkey::r1::measure_decompile(binary.file, decompile_text);
               !counted) {
      measured.error = true;
      measured.error_reason = counted.diagnostic().message;
    } else {
      measured = std::move(counted.value());
    }
    std::string starts_json = "null";
    std::string starts_cell = "";
    if (!measured.error && binary.variant == "stripped") {
      auto twin = donkey::load_binary((work / "out" / binary.unstripped).string());
      if (!twin) {
        measured.error = true;
        measured.error_reason = "cannot load the unstripped twin " + binary.unstripped + ": " +
                                twin.diagnostic().message;
      } else {
        const auto truth = donkey::r1::function_symbol_starts(twin.value().image);
        auto stripped = donkey::load_binary((work / "out" / binary.file).string());
        const auto stubs =
            stripped ? donkey::r1::starts_in_stub_sections(stripped.value().image, measured.starts)
                     : std::set<std::uint64_t>{};
        if (!stripped) {
          measured.error = true;
          measured.error_reason =
              "cannot load " + binary.file + ": " + stripped.diagnostic().message;
        }
        const StartsComparison cmp = donkey::r1::compare_starts(truth, measured.starts, stubs);
        starts_json = "{\"symbols\": " + std::to_string(cmp.truth) +
                      ", \"found\": " + std::to_string(cmp.found) +
                      ", \"matched\": " + std::to_string(cmp.matched) +
                      ", \"missed\": " + std::to_string(cmp.missed) +
                      ", \"stubs\": " + std::to_string(cmp.stubs) +
                      ", \"extra\": " + std::to_string(cmp.extra) + "}";
        starts_cell = std::to_string(cmp.matched) + " of " + std::to_string(cmp.truth) + " (" +
                      std::to_string(cmp.missed) + " missed; " + std::to_string(cmp.stubs) +
                      " stubs, " + std::to_string(cmp.extra) + " extra)";
      }
    }
    if (measured.error) {
      ++errors;
    }
    if (binary.variant == "unstripped" && !measured.error) {
      for (const auto& [note, count] : measured.first_notes) {
        first_notes[note] += count;
      }
      total_functions += measured.functions;
      total_complete += measured.complete;
      total_unexplained += measured.unexplained.size();
    }
    std::string unexplained = "[";
    for (std::size_t i = 0; i < measured.unexplained.size(); ++i) {
      unexplained += (i == 0 ? "" : ", ") + std::string("{\"address\": ") +
                     quote(measured.unexplained[i].address) +
                     ", \"name\": " + quote(measured.unexplained[i].name) + "}";
    }
    unexplained += "]";
    entries +=
        (entries.empty() ? "" : ",\n") + std::string("    {\"file\": ") + quote(binary.file) +
        ", \"build\": " + quote(binary.build) + ", \"toolchain\": " + quote(binary.toolchain) +
        ", \"architecture\": " + quote(binary.architecture) +
        ", \"level\": " + quote(binary.level) + ", \"variant\": " + quote(binary.variant) +
        ", \"compiler\": " + quote(binary.compiler) + ", \"sha256\": " + quote(binary.sha256) +
        ", \"error\": " + (measured.error ? "true" : "false") +
        ", \"error_reason\": " + quote(measured.error_reason) +
        ", \"functions\": " + std::to_string(measured.functions) +
        ", \"complete\": " + std::to_string(measured.complete) +
        ", \"partial\": " + std::to_string(measured.partial) +
        ", \"unsupported\": " + std::to_string(measured.unsupported) +
        ", \"invalid_ir\": " + std::to_string(measured.invalid_ir) +
        ", \"has_notes\": " + (measured.has_notes ? "true" : "false") +
        ", \"analysis_partial\": " + (measured.analysis_partial ? "true" : "false") +
        ", \"analysis_notes\": " + string_array(measured.analysis_notes) +
        ", \"starts\": " + starts_json + ", \"unexplained_partial\": " + unexplained +
        ", \"first_notes\": " + notes_json(measured.first_notes) +
        ", \"all_notes\": " + notes_json(measured.all_notes) + "}";
    rows += "| `" + binary.file + "` | " +
            (measured.error
                 ? "error: " + table_cell(measured.error_reason) + " | | | | | |"
                 : std::to_string(measured.functions) + " | " + std::to_string(measured.complete) +
                       " | " + std::to_string(measured.partial) + " | " +
                       std::to_string(measured.unsupported + measured.invalid_ir) + " | " +
                       std::to_string(measured.unexplained.size()) + " | " + starts_cell + " |") +
            "\n";
  }

  std::string top;
  std::size_t shown = 0;
  for (const auto& [count, note] : ranked(first_notes)) {
    if (shown++ == 20) {
      break;
    }
    top += "| " + std::to_string(count) + " | " + table_cell(note) + " |\n";
  }
  const std::string result =
      "{\n  \"schema\": 1,\n  \"binaries\": [\n" + entries +
      "\n  ],\n  \"unstripped\": {\"functions\": " + std::to_string(total_functions) +
      ", \"complete\": " + std::to_string(total_complete) +
      ", \"unexplained_partial\": " + std::to_string(total_unexplained) +
      ", \"first_notes\": " + notes_json(first_notes) +
      "},\n  \"errors\": " + std::to_string(errors) + "\n}\n";
  const std::string table =
      "| Binary | Functions | Complete | Partial | Unsupported or InvalidIR | Partial, no reason | "
      "Starts found (stripped) |\n|---|---|---|---|---|---|---|\n" +
      rows +
      "\nThe 20 most frequent first notes of Partial functions (unstripped binaries):\n\n"
      "| Partial functions | First specific note |\n|---|---|\n" +
      top;
  if (!write_file(result_path, result) || !write_file(table_path, table)) {
    std::fprintf(stderr, "donkey-r1: cannot write the result\n");
    return 1;
  }
  std::printf(
      "donkey-r1: %zu binaries, %zu with an error; unstripped: %zu of %zu functions Complete\n",
      binaries.value().size(), errors, total_complete, total_functions);
  return errors == 0 ? 0 : 2;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 6 && std::string(argv[1]) == "measure") {
    try {
      return measure(argv[2], argv[3], argv[4], argv[5]);
    } catch (const std::exception& error) {
      std::fprintf(stderr, "donkey-r1: %s\n", error.what());
      return 1;
    }
  }
  std::fprintf(stderr,
               "usage: donkey-r1 measure <work-dir> <decompile-dir> <result.json> <table.md>\n");
  return 1;
}
