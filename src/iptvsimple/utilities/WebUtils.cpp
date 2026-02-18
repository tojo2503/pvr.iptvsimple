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
// Internal helper: lowercase a string in-place without relying on the return
// value of StringUtils::ToLower() (which is void in some NDK builds).
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

char from_hex(char ch)
{
  return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

} // unnamed namespace

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
// PHP-proxy resolver
// ---------------------------------------------------------------------------

std::string WebUtils::Base64UrlToHex(const std::string& input)
{
  // Convert Base64url to standard Base64
  std::string b64 = input;
  for (char& c : b64)
  {
    if (c == '-') c = '+';
    else if (c == '_') c = '/';
  }
  // Add padding
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
  // Format: KID1:KEY1;KID2:KEY2  (hex or Base64url)
  std::map<std::string, std::string> keys;

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

    // Normalise KID to lowercase hex
    std::string kidHex;
    if (kid.length() == 32 &&
        kid.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos)
    {
      kidHex = kid;
      ToLowerInPlace(kidHex);
    }
    else if (kid.length() == 36 && kid[8] == '-') // UUID
    {
      kidHex = kid;
      kidHex.erase(std::remove(kidHex.begin(), kidHex.end(), '-'), kidHex.end());
      ToLowerInPlace(kidHex);
    }
    else
    {
      kidHex = Base64UrlToHex(kid);
    }

    // Normalise KEY to lowercase hex
    std::string keyHex;
    if (key.length() == 32 &&
        key.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos)
    {
      keyHex = key;
      ToLowerInPlace(keyHex);
    }
    else
    {
      keyHex = Base64UrlToHex(key);
    }

    if (!kidHex.empty() && !keyHex.empty())
      keys[kidHex] = keyHex;
    else
      Logger::Log(LEVEL_WARNING, "%s Could not parse clearkey pair: %s", __func__, pair.c_str());
  }
  return keys;
}

std::map<std::string, std::string> WebUtils::ParseAddHeader(const std::string& headerValue)
{
  // Format: Name=Value,Name2=Value2  (comma-separated key=value pairs)
  std::map<std::string, std::string> headers;

  std::istringstream stream(headerValue);
  std::string item;
  while (std::getline(stream, item, ','))
  {
    StringUtils::Trim(item);
    if (item.empty()) continue;
    size_t eqPos = item.find('=');
    if (eqPos == std::string::npos) continue;
    std::string name  = item.substr(0, eqPos);
    std::string value = item.substr(eqPos + 1);
    StringUtils::Trim(name);
    StringUtils::Trim(value);
    if (!name.empty() && !value.empty())
      headers[name] = value;
  }
  return headers;
}

PhpRedirectInfo WebUtils::FetchPhpRedirectInfo(const std::string& phpUrl)
{
  PhpRedirectInfo info;
  info.finalUrl = phpUrl; // fallback: use original URL unchanged

  if (!IsHttpUrl(phpUrl))
    return info;

  // ------------------------------------------------------------------
  // Pass 1: disable redirect following so we can read the 302 headers
  // directly (Location, x-vip-clearkey, x-vip-addheader).
  // ------------------------------------------------------------------
  kodi::vfs::CFile curlFile;
  if (!curlFile.CURLCreate(phpUrl))
  {
    Logger::Log(LEVEL_ERROR, "%s Failed to create CURL handle for %s",
                __func__, RedactUrl(phpUrl).c_str());
    return info;
  }

  // Do NOT follow the redirect – we want the 302 response headers.
  curlFile.CURLAddOption(ADDON_CURL_OPTION_PROTOCOL, "redirect-limit", "0");
  curlFile.CURLAddOption(ADDON_CURL_OPTION_PROTOCOL, "connection-timeout", "10");
  curlFile.CURLAddOption(ADDON_CURL_OPTION_PROTOCOL, "seekable", "0");

  if (!curlFile.CURLOpen(ADDON_READ_NO_CACHE))
  {
    // CURLOpen returns false for non-200 (e.g. 302) – expected.
    Logger::Log(LEVEL_DEBUG, "%s PHP returned non-200 (expected for 302): %s",
                __func__, RedactUrl(phpUrl).c_str());
  }

  // Read Location header (302 redirect target = real MPD URL)
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

  // Read x-vip-clearkey
  const std::string clearKeyHdr =
      curlFile.GetPropertyValue(ADDON_FILE_PROPERTY_RESPONSE_HEADER, "x-vip-clearkey");
  if (!clearKeyHdr.empty())
  {
    info.clearKeys = ParseClearKeyHeader(clearKeyHdr);
    Logger::Log(LEVEL_INFO, "%s x-vip-clearkey: %zu key(s) parsed",
                __func__, info.clearKeys.size());
  }

  // Read x-vip-addheader
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
