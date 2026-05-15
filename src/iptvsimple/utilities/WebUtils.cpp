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
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
    {
      escaped << c;
      continue;
    }
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
  if ((isLocalPath || IsSpecialUrl(strURL)) && FileUtils::FileExists(strURL))
    return true;

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

  const char delimiter = '&';
  const char keyValueSeparator = ':';

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
  std::vector<unsigned char> bytes;
  bytes.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2)
  {
    unsigned int byte = 0;
    std::istringstream ss(hex.substr(i, 2));
    ss >> std::hex >> byte;
    bytes.push_back(static_cast<unsigned char>(byte));
  }

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

  for (char& c : result)
  {
    if (c == '+') c = '-';
    else if (c == '/') c = '_';
  }
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

  Logger::Log(LEVEL_DEBUG, "%s raw x-vip-clearkey header: [%s]", __func__, headerValue.c_str());

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

    Logger::Log(LEVEL_DEBUG, "%s raw KID=[%s] (len=%zu)  KEY=[%s] (len=%zu)",
                __func__, kid.c_str(), kid.length(), key.c_str(), key.length());

    std::string kidHex;
    if (kid.length() == 32 &&
        kid.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos)
    {
      kidHex = kid;
      ToLowerInPlace(kidHex);
      Logger::Log(LEVEL_DEBUG, "%s KID recognised as 32-char hex -> %s", __func__, kidHex.c_str());
    }
    else if (kid.length() == 36 && kid[8] == '-')
    {
      kidHex = kid;
      kidHex.erase(std::remove(kidHex.begin(), kidHex.end(), '-'), kidHex.end());
      ToLowerInPlace(kidHex);
      Logger::Log(LEVEL_DEBUG, "%s KID recognised as UUID -> stripped hex: %s", __func__, kidHex.c_str());
    }
    else
    {
      kidHex = Base64UrlToHex(kid);
      Logger::Log(LEVEL_DEBUG, "%s KID treated as Base64url -> hex: %s", __func__, kidHex.c_str());
    }

    std::string keyHex;
    if (key.length() == 32 &&
        key.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos)
    {
      keyHex = key;
      ToLowerInPlace(keyHex);
      Logger::Log(LEVEL_DEBUG, "%s KEY recognised as 32-char hex -> %s", __func__, keyHex.c_str());
    }
    else
    {
      keyHex = Base64UrlToHex(key);
      Logger::Log(LEVEL_DEBUG, "%s KEY treated as Base64url -> hex: %s", __func__, keyHex.c_str());
    }

    if (!kidHex.empty() && !keyHex.empty())
    {
      Logger::Log(LEVEL_DEBUG, "%s accepted pair  KID=%s  KEY=%s", __func__, kidHex.c_str(), keyHex.c_str());
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
// ParseJsonHeaders: parse a flat JSON object {"Key":"Value",...} into a map.
//
// Used for both x-vip-addheader and x-vip-l1.
// headerName is only used for log messages.
// All standard JSON string escape sequences are handled.
// ---------------------------------------------------------------------------
std::map<std::string, std::string> WebUtils::ParseJsonHeaders(
    const std::string& headerName,
    const std::string& headerValue)
{
  std::map<std::string, std::string> headers;

  Logger::Log(LEVEL_DEBUG, "%s raw %s: [%s]", __func__, headerName.c_str(), headerValue.c_str());

  const std::string& s = headerValue;
  size_t i = 0;
  const size_t n = s.size();

  while (i < n && std::isspace(static_cast<unsigned char>(s[i]))) ++i;

  if (i >= n || s[i] != '{')
  {
    Logger::Log(LEVEL_WARNING,
                "%s %s does not start with '{' - expected JSON object, ignoring",
                __func__, headerName.c_str());
    return headers;
  }
  ++i;

  auto skipWs = [&]() {
    while (i < n && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
  };

  auto readJsonString = [&](std::string& out) -> bool {
    skipWs();
    if (i >= n || s[i] != '"') return false;
    ++i;
    out.clear();
    while (i < n)
    {
      const char c = s[i++];
      if (c == '"') return true;
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
          default:   out += esc;  break;
        }
      }
      else
      {
        out += c;
      }
    }
    return false;
  };

  while (i < n)
  {
    skipWs();
    if (i >= n) break;
    if (s[i] == '}') break;

    std::string key;
    if (!readJsonString(key))
    {
      Logger::Log(LEVEL_WARNING, "%s [%s] Failed to read JSON key at position %zu, aborting",
                  __func__, headerName.c_str(), i);
      break;
    }

    skipWs();
    if (i >= n || s[i] != ':')
    {
      Logger::Log(LEVEL_WARNING, "%s [%s] Expected ':' after key '%s' at position %zu, aborting",
                  __func__, headerName.c_str(), key.c_str(), i);
      break;
    }
    ++i;

    std::string value;
    if (!readJsonString(value))
    {
      Logger::Log(LEVEL_WARNING, "%s [%s] Failed to read JSON value for key '%s' at position %zu, aborting",
                  __func__, headerName.c_str(), key.c_str(), i);
      break;
    }

    Logger::Log(LEVEL_DEBUG, "%s [%s] parsed: [%s] = [%s]",
                __func__, headerName.c_str(), key.c_str(), value.c_str());
    headers[key] = value;

    skipWs();
    if (i < n && s[i] == ',') ++i;
  }

  Logger::Log(LEVEL_INFO, "%s [%s]: %zu header(s) parsed",
              __func__, headerName.c_str(), headers.size());
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

  // --- Location (302 redirect target = MPD URL) ---
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
    Logger::Log(LEVEL_WARNING, "%s No Location header in PHP response, using original URL", __func__);
  }

  // --- x-vip-clearkey: KID:KEY pairs (ClearKey DRM) ---
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

  // --- x-vip-licenceurl: Widevine license server URL ---
  const std::string licenceUrlHdr =
      curlFile.GetPropertyValue(ADDON_FILE_PROPERTY_RESPONSE_HEADER, "x-vip-licenceurl");
  if (!licenceUrlHdr.empty())
  {
    info.licenceUrl = licenceUrlHdr;
    StringUtils::Trim(info.licenceUrl);
    Logger::Log(LEVEL_INFO, "%s x-vip-licenceurl present: [%s]", __func__, RedactUrl(info.licenceUrl).c_str());
    Logger::Log(LEVEL_DEBUG, "%s x-vip-licenceurl raw: [%s]", __func__, info.licenceUrl.c_str());
  }
  else
  {
    Logger::Log(LEVEL_INFO, "%s x-vip-licenceurl header not present", __func__);
  }

  // --- x-vip-l1: headers sent ONLY to the Widevine license server ---
  const std::string l1Hdr =
      curlFile.GetPropertyValue(ADDON_FILE_PROPERTY_RESPONSE_HEADER, "x-vip-l1");
  if (!l1Hdr.empty())
  {
    info.licenceHeaders = ParseJsonHeaders("x-vip-l1", l1Hdr);
    Logger::Log(LEVEL_INFO, "%s x-vip-l1: %zu licence header(s) parsed",
                __func__, info.licenceHeaders.size());
  }
  else
  {
    Logger::Log(LEVEL_INFO, "%s x-vip-l1 header not present", __func__);
  }

  // --- x-vip-addheader: extra headers for MPD + segment requests ---
  const std::string addHdr =
      curlFile.GetPropertyValue(ADDON_FILE_PROPERTY_RESPONSE_HEADER, "x-vip-addheader");
  if (!addHdr.empty())
  {
    info.addHeaders = ParseJsonHeaders("x-vip-addheader", addHdr);
    Logger::Log(LEVEL_INFO, "%s x-vip-addheader: %zu header(s) parsed",
                __func__, info.addHeaders.size());
  }
  else
  {
    Logger::Log(LEVEL_INFO, "%s x-vip-addheader header not present", __func__);
  }

  return info;
}
