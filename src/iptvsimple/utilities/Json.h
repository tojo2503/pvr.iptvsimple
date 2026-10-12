/*
 *  Copyright (C) 2026 tojo2503
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSE.md for more information.
 */

#pragma once

// Minimal JSON reader/writer for the recording server API. Only what the
// API needs: objects, arrays, strings (with \uXXXX incl. surrogates), numbers,
// booleans and null.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace iptvsimple
{
namespace utilities
{
  class JsonValue
  {
  public:
    enum class Type { NUL, BOOL, NUMBER, STRING, ARRAY, OBJECT };

    Type type = Type::NUL;
    bool boolean = false;
    double number = 0;
    std::string string;
    std::vector<JsonValue> array;
    std::map<std::string, JsonValue> object;

    bool IsNull() const { return type == Type::NUL; }
    bool IsObject() const { return type == Type::OBJECT; }
    bool IsArray() const { return type == Type::ARRAY; }

    const JsonValue& operator[](const std::string& key) const
    {
      static const JsonValue nul;
      if (type != Type::OBJECT)
        return nul;
      auto it = object.find(key);
      return it == object.end() ? nul : it->second;
    }

    bool Has(const std::string& key) const { return type == Type::OBJECT && object.count(key) > 0; }

    std::string Str(const std::string& fallback = "") const
    {
      if (type == Type::STRING)
        return string;
      if (type == Type::NUMBER)
        return std::to_string(static_cast<long long>(number));
      return fallback;
    }

    long long Int(long long fallback = 0) const
    {
      if (type == Type::NUMBER)
        return static_cast<long long>(number);
      if (type == Type::BOOL)
        return boolean ? 1 : 0;
      if (type == Type::STRING && !string.empty())
        return std::atoll(string.c_str());
      return fallback;
    }

    double Num(double fallback = 0) const { return type == Type::NUMBER ? number : fallback; }

    bool Bool(bool fallback = false) const
    {
      if (type == Type::BOOL)
        return boolean;
      if (type == Type::NUMBER)
        return number != 0;
      return fallback;
    }
  };

  class Json
  {
  public:
    static bool Parse(const std::string& text, JsonValue& out)
    {
      size_t pos = 0;
      if (!ParseValue(text, pos, out, 0))
        return false;
      SkipWs(text, pos);
      return pos == text.size();
    }

    static std::string Escape(const std::string& s)
    {
      std::string r = "\"";
      for (unsigned char c : s)
      {
        switch (c)
        {
          case '"': r += "\\\""; break;
          case '\\': r += "\\\\"; break;
          case '\n': r += "\\n"; break;
          case '\r': r += "\\r"; break;
          case '\t': r += "\\t"; break;
          default:
            if (c < 0x20)
            {
              char buf[8];
              snprintf(buf, sizeof(buf), "\\u%04x", c);
              r += buf;
            }
            else
              r += static_cast<char>(c);
        }
      }
      return r + "\"";
    }

  private:
    static void SkipWs(const std::string& t, size_t& p)
    {
      while (p < t.size() && (t[p] == ' ' || t[p] == '\n' || t[p] == '\r' || t[p] == '\t'))
        p++;
    }

    static void AppendUtf8(std::string& out, uint32_t cp)
    {
      if (cp < 0x80)
        out += static_cast<char>(cp);
      else if (cp < 0x800)
      {
        out += static_cast<char>(0xC0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3F));
      }
      else if (cp < 0x10000)
      {
        out += static_cast<char>(0xE0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
      }
      else
      {
        out += static_cast<char>(0xF0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
      }
    }

    static bool Hex4(const std::string& t, size_t p, uint32_t& v)
    {
      if (p + 4 > t.size())
        return false;
      v = 0;
      for (size_t i = p; i < p + 4; i++)
      {
        char c = t[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= c - '0';
        else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
        else return false;
      }
      return true;
    }

    static bool ParseString(const std::string& t, size_t& p, std::string& out)
    {
      if (t[p] != '"')
        return false;
      p++;
      while (p < t.size())
      {
        char c = t[p++];
        if (c == '"')
          return true;
        if (c != '\\')
        {
          out += c;
          continue;
        }
        if (p >= t.size())
          return false;
        char e = t[p++];
        switch (e)
        {
          case '"': out += '"'; break;
          case '\\': out += '\\'; break;
          case '/': out += '/'; break;
          case 'b': out += '\b'; break;
          case 'f': out += '\f'; break;
          case 'n': out += '\n'; break;
          case 'r': out += '\r'; break;
          case 't': out += '\t'; break;
          case 'u':
          {
            uint32_t cp;
            if (!Hex4(t, p, cp))
              return false;
            p += 4;
            if (cp >= 0xD800 && cp <= 0xDBFF && p + 6 <= t.size() && t[p] == '\\' && t[p + 1] == 'u')
            {
              uint32_t lo;
              if (Hex4(t, p + 2, lo) && lo >= 0xDC00 && lo <= 0xDFFF)
              {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                p += 6;
              }
            }
            AppendUtf8(out, cp);
            break;
          }
          default:
            return false;
        }
      }
      return false;
    }

    static bool ParseValue(const std::string& t, size_t& p, JsonValue& v, int depth)
    {
      if (depth > 64)
        return false;
      SkipWs(t, p);
      if (p >= t.size())
        return false;
      char c = t[p];
      if (c == '{')
      {
        v.type = JsonValue::Type::OBJECT;
        p++;
        SkipWs(t, p);
        if (p < t.size() && t[p] == '}')
        {
          p++;
          return true;
        }
        while (p < t.size())
        {
          SkipWs(t, p);
          std::string key;
          if (p >= t.size() || !ParseString(t, p, key))
            return false;
          SkipWs(t, p);
          if (p >= t.size() || t[p] != ':')
            return false;
          p++;
          if (!ParseValue(t, p, v.object[key], depth + 1))
            return false;
          SkipWs(t, p);
          if (p < t.size() && t[p] == ',')
          {
            p++;
            continue;
          }
          if (p < t.size() && t[p] == '}')
          {
            p++;
            return true;
          }
          return false;
        }
        return false;
      }
      if (c == '[')
      {
        v.type = JsonValue::Type::ARRAY;
        p++;
        SkipWs(t, p);
        if (p < t.size() && t[p] == ']')
        {
          p++;
          return true;
        }
        while (p < t.size())
        {
          v.array.emplace_back();
          if (!ParseValue(t, p, v.array.back(), depth + 1))
            return false;
          SkipWs(t, p);
          if (p < t.size() && t[p] == ',')
          {
            p++;
            continue;
          }
          if (p < t.size() && t[p] == ']')
          {
            p++;
            return true;
          }
          return false;
        }
        return false;
      }
      if (c == '"')
      {
        v.type = JsonValue::Type::STRING;
        return ParseString(t, p, v.string);
      }
      if (t.compare(p, 4, "true") == 0)
      {
        v.type = JsonValue::Type::BOOL;
        v.boolean = true;
        p += 4;
        return true;
      }
      if (t.compare(p, 5, "false") == 0)
      {
        v.type = JsonValue::Type::BOOL;
        p += 5;
        return true;
      }
      if (t.compare(p, 4, "null") == 0)
      {
        p += 4;
        return true;
      }
      // Locale-independent number parsing (Kodi may run with a ',' decimal locale)
      size_t q = p;
      bool neg = false;
      if (q < t.size() && (t[q] == '-' || t[q] == '+'))
        neg = t[q++] == '-';
      double val = 0;
      size_t digits = 0;
      while (q < t.size() && t[q] >= '0' && t[q] <= '9')
      {
        val = val * 10 + (t[q++] - '0');
        digits++;
      }
      if (q < t.size() && t[q] == '.')
      {
        q++;
        double f = 0.1;
        while (q < t.size() && t[q] >= '0' && t[q] <= '9')
        {
          val += (t[q++] - '0') * f;
          f /= 10;
          digits++;
        }
      }
      if (!digits)
        return false;
      if (q < t.size() && (t[q] == 'e' || t[q] == 'E'))
      {
        q++;
        bool eneg = false;
        if (q < t.size() && (t[q] == '-' || t[q] == '+'))
          eneg = t[q++] == '-';
        int ex = 0;
        while (q < t.size() && t[q] >= '0' && t[q] <= '9')
          ex = ex * 10 + (t[q++] - '0');
        for (int i = 0; i < ex; i++)
          val = eneg ? val / 10 : val * 10;
      }
      v.number = neg ? -val : val;
      v.type = JsonValue::Type::NUMBER;
      p = q;
      return true;
    }
  };

} // namespace utilities
} // namespace iptvsimple
