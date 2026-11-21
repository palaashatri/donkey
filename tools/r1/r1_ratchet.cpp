#include "r1_ratchet.h"

#include <algorithm>
#include <cstdio>
#include <limits>
#include <map>

#include "donkey/core/json.h"

namespace donkey::r1 {

namespace {

Diagnostic ratchet_error(std::string code, std::string message) {
  return Diagnostic::make(Status::InvalidInput, std::move(code), std::move(message), std::nullopt);
}

JsonLimits limits_for(std::size_t size) {
  JsonLimits limits;
  limits.max_bytes = std::max<std::size_t>(size, 1);
  limits.max_nodes = std::max<std::size_t>(size, 1);
  limits.max_depth = 16;
  return limits;
}

/// A non-negative integer member, written without a sign, fraction or exponent.
bool count_member(const JsonValue& object, std::string_view key, std::size_t& out) {
  const JsonValue* value = object.find(key);
  if (value == nullptr || !value->is_number() || value->text.empty() || value->text.size() > 18) {
    return false;
  }
  std::size_t parsed = 0;
  for (const char c : value->text) {
    if (c < '0' || c > '9') {
      return false;
    }
    parsed = parsed * 10 + static_cast<std::size_t>(c - '0');
  }
  out = parsed;
  return true;
}

bool string_member(const JsonValue& object, std::string_view key, std::string& out) {
  const JsonValue* value = object.find(key);
  if (value == nullptr || !value->is_string()) {
    return false;
  }
  out = value->text;
  return true;
}

bool bool_member(const JsonValue& object, std::string_view key, bool& out) {
  const JsonValue* value = object.find(key);
  if (value == nullptr || !value->is_bool()) {
    return false;
  }
  out = value->boolean;
  return true;
}

/// Sorts by file and refuses a file listed twice.
bool sort_unique(std::vector<Counts>& counts) {
  std::sort(counts.begin(), counts.end(),
            [](const Counts& a, const Counts& b) { return a.file < b.file; });
  return std::adjacent_find(counts.begin(), counts.end(), [](const Counts& a, const Counts& b) {
           return a.file == b.file;
         }) == counts.end();
}

bool plain_name(const std::string& file) {
  return !file.empty() && file.find('/') == std::string::npos &&
         file.find('\\') == std::string::npos && file != "." && file != "..";
}

std::string quote(const std::string& text) {
  std::string out = "\"";
  for (const char c : text) {
    if (c == '"' || c == '\\') {
      out += '\\';
      out += c;
    } else if (static_cast<unsigned char>(c) < 0x20) {
      char escaped[8];
      std::snprintf(escaped, sizeof escaped, "\\u%04x", static_cast<unsigned>(c));
      out += escaped;
    } else {
      out += c;
    }
  }
  return out + "\"";
}

std::string describe(std::size_t from, std::size_t to) {
  return std::to_string(from) + " -> " + std::to_string(to);
}

/// Compares one binary's counts with its reference and appends what changed.
void compare(const Counts& reference, const Counts& head, const std::string& against,
             CheckOutcome& out) {
  const std::string where = head.file + " (" + against + ")";
  auto lower_is_better = [&](const char* what, std::size_t from, std::size_t to) {
    if (to > from) {
      out.regressions.push_back(where + ": " + what + " rose, " + describe(from, to));
    } else if (to < from) {
      out.improvements.push_back(where + ": " + what + " fell, " + describe(from, to));
    }
  };
  if (head.complete < reference.complete) {
    out.regressions.push_back(where + ": Complete dropped, " +
                              describe(reference.complete, head.complete));
  } else if (head.complete > reference.complete) {
    out.improvements.push_back(where + ": Complete rose, " +
                               describe(reference.complete, head.complete));
  }
  lower_is_better("Unsupported", reference.unsupported, head.unsupported);
  lower_is_better("InvalidIR", reference.invalid_ir, head.invalid_ir);
  if (head.error && !reference.error) {
    out.regressions.push_back(where + ": the measurement now has an error");
  } else if (!head.error && reference.error) {
    out.improvements.push_back(where + ": the measurement no longer has an error");
  }
  // A stripped binary without missed starts has an error, which is counted above.
  if (reference.missed_starts && head.missed_starts) {
    lower_is_better("missed starts", *reference.missed_starts, *head.missed_starts);
  } else if (reference.missed_starts && !head.error) {
    // A stripped binary whose starts are no longer compared (its variant changed): the count the
    // reference held can no longer be checked.
    out.regressions.push_back(where + ": the missed starts are no longer measured");
  }
}

}  // namespace

Result<std::vector<Counts>> read_baseline(std::string_view json) {
  auto parsed = parse_json(json, limits_for(json.size()));
  if (!parsed) {
    return ratchet_error("r1.bad_baseline",
                         "the baseline is not JSON: " + parsed.diagnostic().message);
  }
  const JsonValue& root = parsed.value();
  const JsonValue* schema = root.find("schema");
  const JsonValue* binaries = root.find("binaries");
  if (!root.is_object() || schema == nullptr || !schema->is_number() || schema->text != "1" ||
      binaries == nullptr || !binaries->is_array()) {
    return ratchet_error("r1.bad_baseline", "the baseline is not a schema 1 list of binaries");
  }
  std::vector<Counts> out;
  for (const JsonValue& entry : binaries->items) {
    Counts counts;
    std::size_t errors = 0;
    if (!entry.is_object() || !string_member(entry, "file", counts.file) ||
        !plain_name(counts.file) || !string_member(entry, "compiler", counts.compiler) ||
        !string_member(entry, "sha256", counts.sha256) || counts.sha256.size() != 64 ||
        !count_member(entry, "complete", counts.complete) ||
        !count_member(entry, "unsupported", counts.unsupported) ||
        !count_member(entry, "invalid_ir", counts.invalid_ir) ||
        !count_member(entry, "error", errors) || errors > 1) {
      return ratchet_error("r1.bad_baseline",
                           "a baseline entry is incomplete: '" + counts.file + "'");
    }
    counts.error = errors == 1;
    const JsonValue* missed = entry.find("missed_starts");
    if (missed == nullptr) {
      return ratchet_error("r1.bad_baseline",
                           "a baseline entry has no missed_starts: '" + counts.file + "'");
    }
    if (!missed->is_null()) {
      std::size_t value = 0;
      if (!count_member(entry, "missed_starts", value)) {
        return ratchet_error(
            "r1.bad_baseline",
            "a baseline entry's missed_starts is not a count: '" + counts.file + "'");
      }
      counts.missed_starts = value;
    }
    out.push_back(std::move(counts));
  }
  if (!sort_unique(out)) {
    return ratchet_error("r1.bad_baseline", "the baseline lists a binary twice");
  }
  return out;
}

Result<std::vector<Counts>> read_result_counts(std::string_view json) {
  auto parsed = parse_json(json, limits_for(json.size()));
  if (!parsed) {
    return ratchet_error("r1.bad_result", "the result is not JSON: " + parsed.diagnostic().message);
  }
  const JsonValue& root = parsed.value();
  const JsonValue* schema = root.find("schema");
  const JsonValue* binaries = root.find("binaries");
  if (!root.is_object() || schema == nullptr || !schema->is_number() || schema->text != "1" ||
      binaries == nullptr || !binaries->is_array()) {
    return ratchet_error("r1.bad_result", "the result is not a schema 1 list of binaries");
  }
  std::vector<Counts> out;
  for (const JsonValue& entry : binaries->items) {
    Counts counts;
    std::string variant;
    if (!entry.is_object() || !string_member(entry, "file", counts.file) ||
        !plain_name(counts.file) || !string_member(entry, "compiler", counts.compiler) ||
        !string_member(entry, "sha256", counts.sha256) || counts.sha256.size() != 64 ||
        !string_member(entry, "variant", variant) || !bool_member(entry, "error", counts.error) ||
        !count_member(entry, "complete", counts.complete) ||
        !count_member(entry, "unsupported", counts.unsupported) ||
        !count_member(entry, "invalid_ir", counts.invalid_ir)) {
      return ratchet_error("r1.bad_result", "a result entry is incomplete: '" + counts.file + "'");
    }
    const JsonValue* starts = entry.find("starts");
    if (variant == "stripped" && !counts.error) {
      std::size_t missed = 0;
      if (starts == nullptr || !starts->is_object() || !count_member(*starts, "missed", missed)) {
        return ratchet_error("r1.bad_result",
                             "a stripped result entry has no missed starts: '" + counts.file + "'");
      }
      counts.missed_starts = missed;
    }
    out.push_back(std::move(counts));
  }
  if (!sort_unique(out)) {
    return ratchet_error("r1.bad_result", "the result lists a binary twice");
  }
  return out;
}

std::string write_baseline(std::vector<Counts> counts) {
  std::sort(counts.begin(), counts.end(),
            [](const Counts& a, const Counts& b) { return a.file < b.file; });
  std::string out = "{\n  \"schema\": 1,\n  \"binaries\": [\n";
  for (std::size_t i = 0; i < counts.size(); ++i) {
    const Counts& c = counts[i];
    out += "    {\"file\": " + quote(c.file) + ", \"compiler\": " + quote(c.compiler) +
           ", \"sha256\": " + quote(c.sha256) + ", \"complete\": " + std::to_string(c.complete) +
           ", \"unsupported\": " + std::to_string(c.unsupported) +
           ", \"invalid_ir\": " + std::to_string(c.invalid_ir) +
           ", \"error\": " + (c.error ? "1" : "0") + ", \"missed_starts\": " +
           (c.missed_starts ? std::to_string(*c.missed_starts) : std::string("null")) + "}" +
           (i + 1 < counts.size() ? "," : "") + "\n";
  }
  return out + "  ]\n}\n";
}

CheckOutcome check(const std::vector<Counts>& baseline, const std::vector<Counts>& head,
                   const std::vector<Counts>* base_measured) {
  CheckOutcome out;
  std::map<std::string, const Counts*> stored;
  for (const Counts& c : baseline) {
    stored.emplace(c.file, &c);
  }
  std::map<std::string, const Counts*> measured;
  if (base_measured != nullptr) {
    for (const Counts& c : *base_measured) {
      measured.emplace(c.file, &c);
    }
  }
  std::map<std::string, bool> seen;
  for (const Counts& now : head) {
    seen[now.file] = true;
    const auto entry = stored.find(now.file);
    if (entry != stored.end() && entry->second->sha256 == now.sha256) {
      compare(*entry->second, now, "against the baseline", out);
      continue;
    }
    // The baseline describes other bytes, or none: the base CLI's count of these bytes is the
    // reference.
    const auto base = measured.find(now.file);
    if (base == measured.end() || base->second->sha256 != now.sha256) {
      out.needs_base.push_back(now.file);
      continue;
    }
    const std::size_t before = out.regressions.size();
    compare(*base->second, now, "against the base CLI on the same bytes", out);
    if (out.regressions.size() == before) {
      out.warnings.push_back(now.file + ": the baseline is out of date (" +
                             (entry == stored.end()
                                  ? std::string("a new binary")
                                  : "other bytes, compiler " + entry->second->compiler + " then, " +
                                        now.compiler + " now") +
                             "); re-record it with donkey-r1 baseline");
    }
  }
  for (const Counts& old : baseline) {
    if (seen.count(old.file) == 0) {
      out.removed.push_back(old.file);
    }
  }
  return out;
}

}  // namespace donkey::r1
