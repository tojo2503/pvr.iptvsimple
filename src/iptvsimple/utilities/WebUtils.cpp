/*
 *  Copyright (C) 2005-2021 Team Kodi (https://kodi.tv)
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSE.md for more information.
 */

#include "WebUtils.h"

#include "FileUtils.h"
#include "Logger.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>

#include <kodi/Filesystem.h>
#include <kodi/tools/StringUtils.h>

using namespace kodi::tools;
using namespace iptvsimple;
using namespace iptvsimple::utilities;

// ---------------------------------------------------------------------------
// Internal helper: lowercase a string in-place
// ---------------------------------------------------------------------------
static void ToLowerInPlace(std::string& s)
{
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
}

// http://stackoverflow.com/a/17708801
const std::string WebUtils::UrlEncode(const std::string& value)
{
  std::ostringstream escaped;
  escaped.fill('0');
  escaped << std::hex;

  for (auto c : value)
  {
    // Keep alphanumeric and other accepted characters intact
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
    {
      escaped << c;
      continue;
    }

    // Any other characters are percent-encoded
    escaped << '%' << std::setw(2) << int(static_cast<unsigned char>(c));
  }

  return escaped.str();
}

namespace
{

char from_hex(char ch) {
    return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

} // unamed namespace

const std::string WebUtils::UrlDecode(const std::string& value)
{
  char h;
  std::ostringstream escaped;
  escaped.fill('0');

  for (auto i = value.begin(), n = value.end(); i != n; ++i)
  {
    std::string::value_type c = (*i);

    if (c == '%')
    {
      if (i[1] && i[2])
      {
        h = from_hex(i[1]) << 4 | from_hex(i[2]);
        escaped << h;
        i += 2;
      }
    }
    else if (c == '+')
    {
      escaped << ' ';
    }
    else
    {
      escaped << c;
    }
  }

  return escaped.str();
}

bool WebUtils::IsEncoded(const std::string& value)
{
  // Note this is not perfect as '+' symbols will mess this up, they should in general be avoided in preference of '%20'
  return UrlDecode(value) != value;
}

std::string WebUtils::ReadFileContentsStartOnly(const std::string& url, int* httpCode)
{
  std::string strContent;
  kodi::vfs::CFile file;

  if (file.OpenFile(url, ADDON_READ_NO_CACHE))
  {
    char buffer[1024];
    if (int bytesRead = file.Read(buffer, 1024))
      strContent.append(buffer, bytesRead);
  }

  if (strContent.empty())
    *httpCode = 500;
  else
    *httpCode = 200;

  return strContent;
}

bool WebUtils::IsHttpUrl(const std::string& url)
{
  return StringUtils::StartsWith(url, HTTP_PREFIX) || StringUtils::StartsWith(url, HTTPS_PREFIX);
}

bool WebUtils::IsNfsUrl(const std::string& url)
{
  return StringUtils::StartsWith(url, NFS_PREFIX);
}

bool WebUtils::IsSpecialUrl(const std::string& url)
{
  return StringUtils::StartsWith(url, SPECIAL_PREFIX);
}

std::string WebUtils::RedactUrl(const std::string& url)
{
  std::string redactedUrl = url;
  static const std::regex regex("^(http:|https:)//[^@/]+:[^@/]+@.*$");
  if (std::regex_match(url, regex))
  {
    std::string protocol = url.substr(0, url.find_first_of(":"));
    std::string fullPrefix = url.substr(url.find_first_of("@") + 1);

    redactedUrl = protocol + "://USERNAME:PASSWORD@" + fullPrefix;
  }

  return redactedUrl;
}

bool WebUtils::Check(const std::string& strURL, int connectionTimeoutSecs, bool isLocalPath)
{
  // For local paths we only need to check existence of the file
  if ((isLocalPath || IsSpecialUrl(strURL)) && FileUtils::FileExists(strURL))
    return true;

  // Otherwise it's remote
  kodi::vfs::CFile fileHandle;
  if (!fileHandle.CURLCreate(strURL))
  {
    Logger::Log(LEVEL_ERROR, "%s Unable to create curl handle for %s", __func__, WebUtils::RedactUrl(strURL).c_str());
    return false;
  }

  if (!IsNfsUrl(strURL))
    fileHandle.CURLAddOption(ADDON_CURL_OPTION_PROTOCOL, "connection-timeout", std::to_string(connectionTimeoutSecs));

  if (!fileHandle.CURLOpen(ADDON_READ_NO_CACHE))
  {
    Logger::Log(LEVEL_DEBUG, "%s Unable to open url: %s", __func__, WebUtils::RedactUrl(strURL).c_str());
    return false;
  }

  return true;
}

std::map<std::string, std::string> WebUtils::ConvertStringToHeaders(const std::string& input)
{
  std::map<std::string, std::string> result;
  std::istringstream stream(input);
  std::string item;

  const char delimiter = '&'; // Default delimiter
  const char keyValueSeparator = ':'; // Default key-value separator

  while (std::getline(stream, item, delimiter))
  {
    size_t pos = item.find(keyValueSeparator);
    if (pos != std::string::npos)
    {
      std::string key = item.substr(0, pos);
      std::string value = item.substr(pos + 1);
      result[key] = value;
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// HexToBase64Url: convert 32-char hex (16 bytes) -> Base64url without padding
// ---------------------------------------------------------------------------
std::string WebUtils::HexToBase64Url(const std::string& hex)
{
  // Decode hex -> bytes
  std::vector<unsigned char> bytes;
  bytes.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2)
  {
    unsigned int byte = 0;
    std::istringstream ss(hex.substr(i, 2));
    ss >> std::hex >> byte;
    bytes.push_back(static_cast<unsigned char>(byte));
  }

  // Base64 encode
  static const char* b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string result;
  result.reserve(((bytes.size() + 2) / 3) * 4);

  for (size_t i = 0; i < bytes.size(); i += 3)
  {
    unsigned int b = (bytes[i] << 16);
    if (i + 1 < bytes.size()) b |= (bytes[i + 1] << 8);
    if (i + 2 < bytes.size()) b |= bytes[i + 2];

    result += b64chars[(b >> 18) & 0x3F];
    result += b64chars[(b >> 12) & 0x3F];
    result += (i + 1 < bytes.size()) ? b64chars[(b >> 6) & 0x3F] : '=';
    result += (i + 2 < bytes.size()) ? b64chars[b & 0x3F] : '=';
  }

  // Convert to Base64url: + -> -, / -> _, strip padding
  for (char& c : result)
  {
    if (c == '+') c = '-';
    else if (c == '/') c = '_';
  }
  // Remove padding
  while (!result.empty() && result.back() == '=')
    result.pop_back();

  return result;
}

// ---------------------------------------------------------------------------
// PHP-proxy resolver
// ---------------------------------------------------------------------------

std::string WebUtils::Base64UrlToHex(const std::string& input)
{
  std::string b64 = input;
  for (char& c : b64)
  {
    if (c == '-') c = '+';
    else if (c == '_') c = '/';
  }
  while (b64.size() % 4 != 0)
    b64 += '=';

  static const std::string base64Chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  std::string hexOut;
  int val = 0, valb = -8;
  for (unsigned char c : b64)
  {
    if (c == '=') break;
    size_t pos = base64Chars.find(c);
    if (pos == std::string::npos) continue;
    val = (val << 6) + static_cast<int>(pos);
    valb += 6;
    if (valb >= 0)
    {
      unsigned char byte = static_cast<unsigned char>((val >> valb) & 0xFF);
      char buf[3];
      snprintf(buf, sizeof(buf), "%02x", byte);
      hexOut += buf;
      valb -= 8;
    }
  }
  return hexOut;
}

std::map<std::string, std::string> WebUtils::ParseClearKeyHeader(const std::string& headerValue)
{
  std::map<std::string, std::string> keys;

  Logger::Log(LEVEL_INFO, "%s raw x-vip-clearkey header: [%s]", __func__, headerValue.c_str());

  std::istringstream stream(headerValue);
  std::string pair;
  while (std::getline(stream, pair, ';'))
  {
    StringUtils::Trim(pair);
    if (pair.empty()) continue;

    size_t colonPos = pair.find(':');
    if (colonPos == std::string::npos) continue;

    std::string kid = pair.substr(0, colonPos);
    std::string key = pair.substr(colonPos + 1);
    StringUtils::Trim(kid);
    StringUtils::Trim(key);
    if (kid.empty() || key.empty()) continue;

    Logger::Log(LEVEL_INFO, "%s raw KID=[%s] (len=%zu)  KEY=[%s] (len=%zu)",
                __func__, kid.c_str(), kid.length(), key.c_str(), key.length());

    std::string kidHex;
    if (kid.length() == 32 &&
        kid.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos)
    {
      kidHex = kid;
      ToLowerInPlace(kidHex);
      Logger::Log(LEVEL_INFO, "%s KID recognised as 32-char hex -> %s", __func__, kidHex.c_str());
    }
    else if (kid.length() == 36 && kid[8] == '-')
    {
      kidHex = kid;
      kidHex.erase(std::remove(kidHex.begin(), kidHex.end(), '-'), kidHex.end());
      ToLowerInPlace(kidHex);
      Logger::Log(LEVEL_INFO, "%s KID recognised as UUID -> stripped hex: %s", __func__, kidHex.c_str());
    }
    else
    {
      kidHex = Base64UrlToHex(kid);
      Logger::Log(LEVEL_INFO, "%s KID treated as Base64url -> hex: %s", __func__, kidHex.c_str());
    }

    std::string keyHex;
    if (key.length() == 32 &&
        key.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos)
    {
      keyHex = key;
      ToLowerInPlace(keyHex);
      Logger::Log(LEVEL_INFO, "%s KEY recognised as 32-char hex -> %s", __func__, keyHex.c_str());
    }
    else
    {
      keyHex = Base64UrlToHex(key);
      Logger::Log(LEVEL_INFO, "%s KEY treated as Base64url -> hex: %s", __func__, keyHex.c_str());
    }

    if (!kidHex.empty() && !keyHex.empty())
    {
      Logger::Log(LEVEL_INFO, "%s accepted pair  KID=%s  KEY=%s", __func__, kidHex.c_str(), keyHex.c_str());
      keys[kidHex] = keyHex;
    }
    else
    {
      Logger::Log(LEVEL_WARNING, "%s Could not parse clearkey pair: %s", __func__, pair.c_str());
    }
  }
  return keys;
}

// ---------------------------------------------------------------------------
// ParseAddHeader: parse x-vip-addheader as a flat JSON object.
//
// Expected PHP format:
//   {"Header-Name":"value","Another-Header":"value with \"quotes\" and commas, etc."}
//
// The old comma/equals format ("Key=Value,Key=Value") is no longer supported.
// A hand-rolled parser is used so no additional JSON library dependency is needed.
// All standard JSON string escape sequences are handled (\", \\, \/, \n, \r, \t).
// ---------------------------------------------------------------------------
std::map<std::string, std::string> WebUtils::ParseAddHeader(const std::string& headerValue)
{
  std::map<std::string, std::string> headers;

  Logger::Log(LEVEL_INFO, "%s raw x-vip-addheader: [%s]", __func__, headerValue.c_str());

  const std::string& s = headerValue;
  size_t i = 0;
  const size_t n = s.size();

  // --- skip leading whitespace and locate opening '{' ---
  while (i < n && std::isspace(static_cast<unsigned char>(s[i]))) ++i;

  if (i >= n || s[i] != '{')
  {
    Logger::Log(LEVEL_WARNING,
                "%s x-vip-addheader does not start with '{' – expected JSON object, ignoring",
                __func__);
    return headers;
  }
  ++i; // consume '{'

  // --- local helpers via lambdas ---

  auto skipWs = [&]() {
    while (i < n && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
  };

  // Read a JSON-encoded string.  Cursor must be positioned at the opening '"'.
  // Returns true and fills `out` on success; returns false on parse error.
  auto readJsonString = [&](std::string& out) -> bool {
    skipWs();
    if (i >= n || s[i] != '"') return false;
    ++i; // consume opening '"'
    out.clear();
    while (i < n)
    {
      const char c = s[i++];
      if (c == '"')
        return true; // closing quote – done

      if (c == '\\' && i < n)
      {
        const char esc = s[i++];
        switch (esc)
        {
          case '"':  out += '"';  break;
          case '\\': out += '\\'; break;
          case '/':  out += '/';  break;
          case 'n':  out += '\n'; break;
          case 'r':  out += '\r'; break;
          case 't':  out += '\t'; break;
          default:   out += esc;  break; // pass through unknown escapes
        }
      }
      else
      {
        out += c;
      }
    }
    return false; // unterminated string
  };

  // --- main parse loop ---
  while (i < n)
  {
    skipWs();
    if (i >= n) break;
    if (s[i] == '}') break; // end of JSON object

    // Read key
    std::string key;
    if (!readJsonString(key))
    {
      Logger::Log(LEVEL_WARNING, "%s Failed to read JSON key at position %zu, aborting",
                  __func__, i);
      break;
    }

    // Expect ':'
    skipWs();
    if (i >= n || s[i] != ':')
    {
      Logger::Log(LEVEL_WARNING,
                  "%s Expected ':' after key '%s' at position %zu, aborting",
                  __func__, key.c_str(), i);
      break;
    }
    ++i; // consume ':'

    // Read value
    std::string value;
    if (!readJsonString(value))
    {
      Logger::Log(LEVEL_WARNING,
                  "%s Failed to read JSON value for key '%s' at position %zu, aborting",
                  __func__, key.c_str(), i);
      break;
    }

    Logger::Log(LEVEL_INFO, "%s addheader parsed: [%s] = [%s]",
                __func__, key.c_str(), value.c_str());
    headers[key] = value;

    // Optional trailing comma before next pair
    skipWs();
    if (i < n && s[i] == ',') ++i;
  }

  Logger::Log(LEVEL_INFO, "%s x-vip-addheader: %zu header(s) parsed",
              __func__, headers.size());
  return headers;
}

PhpRedirectInfo WebUtils::FetchPhpRedirectInfo(const std::string& phpUrl)
{
  PhpRedirectInfo info;
  info.finalUrl = phpUrl;

  if (!IsHttpUrl(phpUrl))
    return info;

  kodi::vfs::CFile curlFile;
  if (!curlFile.CURLCreate(phpUrl))
  {
    Logger::Log(LEVEL_ERROR, "%s Failed to create CURL handle for %s",
                __func__, RedactUrl(phpUrl).c_str());
    return info;
  }

  curlFile.CURLAddOption(ADDON_CURL_OPTION_PROTOCOL, "redirect-limit", "0");
  curlFile.CURLAddOption(ADDON_CURL_OPTION_PROTOCOL, "connection-timeout", "10");
  curlFile.CURLAddOption(ADDON_CURL_OPTION_PROTOCOL, "seekable", "0");

  if (!curlFile.CURLOpen(ADDON_READ_NO_CACHE))
  {
    Logger::Log(LEVEL_DEBUG, "%s PHP returned non-200 (expected for 302): %s",
                __func__, RedactUrl(phpUrl).c_str());
  }

  const std::string location =
      curlFile.GetPropertyValue(ADDON_FILE_PROPERTY_RESPONSE_HEADER, "location");
  if (!location.empty())
  {
    info.finalUrl = location;
    info.resolved = true;
    Logger::Log(LEVEL_INFO, "%s PHP 302 -> MPD URL: %s",
                __func__, RedactUrl(location).c_str());
  }
  else
  {
    Logger::Log(LEVEL_WARNING,
                "%s No Location header in PHP response, using original URL", __func__);
  }

  const std::string clearKeyHdr =
      curlFile.GetPropertyValue(ADDON_FILE_PROPERTY_RESPONSE_HEADER, "x-vip-clearkey");
  if (!clearKeyHdr.empty())
  {
    info.clearKeys = ParseClearKeyHeader(clearKeyHdr);
    Logger::Log(LEVEL_INFO, "%s x-vip-clearkey: %zu key(s) parsed",
                __func__, info.clearKeys.size());
  }
  else
  {
    Logger::Log(LEVEL_INFO, "%s x-vip-clearkey header not present", __func__);
  }

  const std::string addHdr =
      curlFile.GetPropertyValue(ADDON_FILE_PROPERTY_RESPONSE_HEADER, "x-vip-addheader");
  if (!addHdr.empty())
  {
    info.addHeaders = ParseAddHeader(addHdr);
    Logger::Log(LEVEL_INFO, "%s x-vip-addheader: %zu header(s) parsed",
                __func__, info.addHeaders.size());
  }

  return info;
}
