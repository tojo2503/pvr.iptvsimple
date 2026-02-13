/*
 *  Copyright (C) 2005-2021 Team Kodi (https://kodi.tv)
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSE.md for more information.
 */

#include "WebUtils.h"

#include "FileUtils.h"
#include "Logger.h"

#include <cctype>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <regex>

#include <kodi/Filesystem.h>
#include <kodi/tools/StringUtils.h>

using namespace kodi::tools;
using namespace iptvsimple;
using namespace iptvsimple::utilities;

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

  //Otherwise it's remote
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

// ==================== PHP 302-Redirect Handler ====================

bool WebUtils::IsDynamicUrl(const std::string& url)
{
  // Check if URL is dynamic (PHP, API, etc.)
  std::string lowerUrl = url;
  std::transform(lowerUrl.begin(), lowerUrl.end(), lowerUrl.begin(), ::tolower);

  // Check for dynamic file extensions
  static const std::vector<std::string> dynamicExtensions = {".php", ".asp", ".aspx", ".jsp", ".cgi"};
  for (const auto& ext : dynamicExtensions)
  {
    if (lowerUrl.find(ext) != std::string::npos)
      return true;
  }

  // Check for query parameters (often dynamic)
  if (url.find('?') != std::string::npos)
    return true;

  // Check for API paths
  if (lowerUrl.find("/api/") != std::string::npos || 
      lowerUrl.find("/v1/") != std::string::npos || 
      lowerUrl.find("/v2/") != std::string::npos)
    return true;

  return false;
}

PhpDynamicData WebUtils::FetchDynamicDataAndResolveUrl(const std::string& url, 
                                                        const std::map<std::string, std::string>& existingHeaders)
{
  PhpDynamicData result;
  result.finalUrl = url; // Default: use original URL

  Logger::Log(LEVEL_DEBUG, "[PHP-Handler] Fetching dynamic data from: %s", WebUtils::RedactUrl(url).c_str());

  kodi::vfs::CFile fileHandle;
  if (!fileHandle.CURLCreate(url))
  {
    Logger::Log(LEVEL_ERROR, "[PHP-Handler] Unable to create curl handle for %s", WebUtils::RedactUrl(url).c_str());
    return result;
  }

  // Add existing headers (e.g., User-Agent from KODIPROP)
  for (const auto& header : existingHeaders)
  {
    fileHandle.CURLAddOption(ADDON_CURL_OPTION_HEADER, header.first, header.second);
  }

  // Enable header capture
  fileHandle.CURLAddOption(ADDON_CURL_OPTION_PROTOCOL, "seekable", "0");
  fileHandle.CURLAddOption(ADDON_CURL_OPTION_PROTOCOL, "acceptencoding", "gzip, deflate");

  if (!fileHandle.CURLOpen(ADDON_READ_NO_CACHE))
  {
    Logger::Log(LEVEL_ERROR, "[PHP-Handler] Unable to open url: %s", WebUtils::RedactUrl(url).c_str());
    return result;
  }

  // Get response code
  std::string responseCode = fileHandle.GetPropertyValue(ADDON_FILE_PROPERTY_RESPONSE_PROTOCOL, "response_code");
  int httpCode = responseCode.empty() ? 200 : std::atoi(responseCode.c_str());

  Logger::Log(LEVEL_DEBUG, "[PHP-Handler] HTTP Response Code: %d", httpCode);

  // Check for 302/301/307 redirect
  if (httpCode == 302 || httpCode == 301 || httpCode == 307)
  {
    // Get Location header (final MPD URL)
    std::string location = fileHandle.GetPropertyValue(ADDON_FILE_PROPERTY_RESPONSE_HEADER, "Location");
    if (location.empty())
      location = fileHandle.GetPropertyValue(ADDON_FILE_PROPERTY_RESPONSE_HEADER, "location");

    if (!location.empty())
    {
      result.finalUrl = location;
      result.hasRedirect = true;
      Logger::Log(LEVEL_INFO, "[PHP-Handler] 302 Redirect detected -> %s", location.substr(0, 60).c_str());
    }
    else
    {
      Logger::Log(LEVEL_WARNING, "[PHP-Handler] 302 Redirect without Location header");
    }
  }

  // Get x-vip-clearkey header (DRM keys)
  std::string clearKeyHeader = fileHandle.GetPropertyValue(ADDON_FILE_PROPERTY_RESPONSE_HEADER, "x-vip-clearkey");
  if (clearKeyHeader.empty())
    clearKeyHeader = fileHandle.GetPropertyValue(ADDON_FILE_PROPERTY_RESPONSE_HEADER, "X-VIP-Clearkey");

  if (!clearKeyHeader.empty())
  {
    Logger::Log(LEVEL_INFO, "[PHP-Handler] x-vip-clearkey header found: %s", clearKeyHeader.c_str());
    result.keys = ParseHeaderKeys(clearKeyHeader);
    result.hasKeys = !result.keys.empty();

    if (result.hasKeys)
    {
      Logger::Log(LEVEL_INFO, "[PHP-Handler] Extracted %d key(s) from x-vip-clearkey", (int)result.keys.size());
    }
  }

  // Get x-vip-addheader header (additional HTTP headers)
  std::string addHeaderValue = fileHandle.GetPropertyValue(ADDON_FILE_PROPERTY_RESPONSE_HEADER, "x-vip-addheader");
  if (addHeaderValue.empty())
    addHeaderValue = fileHandle.GetPropertyValue(ADDON_FILE_PROPERTY_RESPONSE_HEADER, "X-VIP-Addheader");

  if (!addHeaderValue.empty())
  {
    Logger::Log(LEVEL_INFO, "[PHP-Handler] x-vip-addheader header found: %s", addHeaderValue.c_str());
    result.headers = ParseAddHeaders(addHeaderValue);
    result.hasHeaders = !result.headers.empty();

    if (result.hasHeaders)
    {
      Logger::Log(LEVEL_INFO, "[PHP-Handler] Extracted %d header(s) from x-vip-addheader", (int)result.headers.size());
    }
  }

  return result;
}

// ==================== Key Parsing ====================

std::map<std::string, std::string> WebUtils::ParseHeaderKeys(const std::string& headerValue)
{
  std::map<std::string, std::string> keys;

  // Format: KID:KEY;KID:KEY;KID:KEY
  std::istringstream stream(headerValue);
  std::string pair;

  while (std::getline(stream, pair, ';'))
  {
    // Trim whitespace
    pair.erase(0, pair.find_first_not_of(" \t"));
    pair.erase(pair.find_last_not_of(" \t") + 1);

    if (pair.empty())
      continue;

    size_t colonPos = pair.find(':');
    if (colonPos == std::string::npos)
    {
      Logger::Log(LEVEL_WARNING, "[PHP-Handler] Invalid key pair (missing colon): %s", pair.c_str());
      continue;
    }

    std::string kid = pair.substr(0, colonPos);
    std::string key = pair.substr(colonPos + 1);

    // Trim
    kid.erase(0, kid.find_first_not_of(" \t"));
    kid.erase(kid.find_last_not_of(" \t") + 1);
    key.erase(0, key.find_first_not_of(" \t"));
    key.erase(key.find_last_not_of(" \t") + 1);

    if (kid.empty() || key.empty())
    {
      Logger::Log(LEVEL_WARNING, "[PHP-Handler] Invalid key pair (empty KID or Key): %s", pair.c_str());
      continue;
    }

    try
    {
      // Convert to Hex (supports Hex, Base64url, UUID)
      std::string kidHex = Base64urlToHex(kid);
      std::string keyHex = Base64urlToHex(key);

      if (!kidHex.empty() && !keyHex.empty())
      {
        keys[kidHex] = keyHex;
        Logger::Log(LEVEL_DEBUG, "[PHP-Handler] Key pair loaded: %s... -> %s...", 
                    kidHex.substr(0, 8).c_str(), keyHex.substr(0, 8).c_str());
      }
    }
    catch (const std::exception& e)
    {
      Logger::Log(LEVEL_ERROR, "[PHP-Handler] Error parsing key pair %s: %s", pair.c_str(), e.what());
    }
  }

  return keys;
}

std::map<std::string, std::string> WebUtils::ParseAddHeaders(const std::string& headerValue)
{
  std::map<std::string, std::string> headers;

  // Format: key=value,key2=value2 or key=value;key2=value2
  char separator = headerValue.find(';') != std::string::npos ? ';' : ',';

  std::istringstream stream(headerValue);
  std::string pair;

  while (std::getline(stream, pair, separator))
  {
    // Trim whitespace
    pair.erase(0, pair.find_first_not_of(" \t"));
    pair.erase(pair.find_last_not_of(" \t") + 1);

    if (pair.empty())
      continue;

    size_t equalPos = pair.find('=');
    if (equalPos == std::string::npos)
    {
      Logger::Log(LEVEL_WARNING, "[PHP-Handler] Invalid header pair (missing =): %s", pair.c_str());
      continue;
    }

    std::string key = pair.substr(0, equalPos);
    std::string value = pair.substr(equalPos + 1);

    // Trim
    key.erase(0, key.find_first_not_of(" \t"));
    key.erase(key.find_last_not_of(" \t") + 1);
    value.erase(0, value.find_first_not_of(" \t"));
    value.erase(value.find_last_not_of(" \t") + 1);

    if (key.empty() || value.empty())
    {
      Logger::Log(LEVEL_WARNING, "[PHP-Handler] Invalid header pair (empty key or value): %s", pair.c_str());
      continue;
    }

    headers[key] = value;
    Logger::Log(LEVEL_DEBUG, "[PHP-Handler] Dynamic header loaded: %s = %s", key.c_str(), value.c_str());
  }

  return headers;
}

// ==================== Base64url / Hex Conversion ====================

std::string WebUtils::Base64urlToHex(const std::string& input)
{
  // Already Hex? (32 chars, only 0-9a-fA-F)
  if (input.length() == 32)
  {
    bool isHex = true;
    for (char c : input)
    {
      if (!std::isxdigit(c))
      {
        isHex = false;
        break;
      }
    }
    if (isHex)
    {
      std::string result = input;
      std::transform(result.begin(), result.end(), result.begin(), ::tolower);
      return result;
    }
  }

  // UUID format? (36 chars with dashes)
  if (input.length() == 36 && input.find('-') != std::string::npos)
  {
    std::string result = input;
    result.erase(std::remove(result.begin(), result.end(), '-'), result.end());
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
  }

  // Base64 or Base64url -> Convert to Hex
  std::string base64 = input;

  // Base64url to Base64
  if (input.find('-') != std::string::npos || input.find('_') != std::string::npos)
  {
    base64 = input;
    std::replace(base64.begin(), base64.end(), '-', '+');
    std::replace(base64.begin(), base64.end(), '_', '/');
  }

  // Add padding if missing
  while (base64.length() % 4)
    base64 += '=';

  // Base64 decode
  static const std::string base64_chars = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  std::string decoded;
  std::vector<int> T(256, -1);
  for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;

  int val = 0, valb = -8;
  for (unsigned char c : base64)
  {
    if (T[c] == -1) break;
    val = (val << 6) + T[c];
    valb += 6;
    if (valb >= 0)
    {
      decoded.push_back(char((val >> valb) & 0xFF));
      valb -= 8;
    }
  }

  // Convert bytes to hex
  std::ostringstream hex;
  hex << std::hex << std::setfill('0');
  for (unsigned char c : decoded)
  {
    hex << std::setw(2) << static_cast<int>(c);
  }

  return hex.str();
}

std::string WebUtils::HexToBase64url(const std::string& hex)
{
  // Convert hex string to bytes
  std::string bytes;
  for (size_t i = 0; i < hex.length(); i += 2)
  {
    std::string byteString = hex.substr(i, 2);
    char byte = static_cast<char>(std::stoi(byteString, nullptr, 16));
    bytes.push_back(byte);
  }

  // Base64 encode
  static const std::string base64_chars = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  std::string base64;
  int val = 0, valb = -6;
  for (unsigned char c : bytes)
  {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0)
    {
      base64.push_back(base64_chars[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6) base64.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);

  // Base64 to Base64url (replace + with -, / with _, remove padding)
  std::replace(base64.begin(), base64.end(), '+', '-');
  std::replace(base64.begin(), base64.end(), '/', '_');
  base64.erase(std::remove(base64.begin(), base64.end(), '='), base64.end());

  return base64;
}

// ==================== Clearkey JSON Generator ====================

std::string WebUtils::GenerateClearkeyJson(const std::map<std::string, std::string>& keys)
{
  if (keys.empty())
    return "";

  // Generate inputstream.adaptive clearkey JSON
  // Format: {"keys":[{"kty":"oct","kid":"...","k":"..."}]}

  std::ostringstream json;
  json << "{\"keys\":[";

  bool first = true;
  for (const auto& pair : keys)
  {
    if (!first)
      json << ",";
    first = false;

    std::string kidBase64url = HexToBase64url(pair.first);
    std::string keyBase64url = HexToBase64url(pair.second);

    json << "{\"kty\":\"oct\","
         << "\"kid\":\"" << kidBase64url << "\","
         << "\"k\":\"" << keyBase64url << "\"}";
  }

  json << "]}";

  return json.str();
}
