/*
 *  Copyright (C) 2005-2021 Team Kodi (https://kodi.tv)
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSE.md for more information.
 */

#pragma once

#include <map>
#include <string>

namespace iptvsimple
{
  namespace utilities
  {
    static const std::string HTTP_PREFIX = "http://";
    static const std::string HTTPS_PREFIX = "https://";
    static const std::string NFS_PREFIX = "nfs://";
    static const std::string SPECIAL_PREFIX = "special://";
    static const std::string UDP_MULTICAST_PREFIX = "udp://@";
    static const std::string RTP_MULTICAST_PREFIX = "rtp://@";

    // PHP Response Data Structure (x-vip-clearkey, x-vip-addheader, Location)
    struct PhpDynamicData
    {
      std::string finalUrl;                             // Final MPD URL from Location header
      std::map<std::string, std::string> keys;          // Clearkey KID:Key pairs (hex format)
      std::map<std::string, std::string> headers;       // Additional HTTP headers
      bool hasKeys = false;
      bool hasHeaders = false;
      bool hasRedirect = false;
    };

    class WebUtils
    {
    public:
      static const std::string UrlEncode(const std::string& value);
      static const std::string UrlDecode(const std::string& value);
      static bool IsEncoded(const std::string& value);
      static std::string ReadFileContentsStartOnly(const std::string& url, int* httpCode);
      static bool IsHttpUrl(const std::string& url);
      static bool IsNfsUrl(const std::string& url);
      static bool IsSpecialUrl(const std::string& url);
      static std::string RedactUrl(const std::string& url);
      static bool Check(const std::string& url, int connectionTimeoutSecs, bool isLocalPath = false);
      static std::map<std::string, std::string> ConvertStringToHeaders(const std::string& input);

      // PHP 302-Redirect Handler with x-vip-clearkey and x-vip-addheader support
      static bool IsDynamicUrl(const std::string& url);
      static PhpDynamicData FetchDynamicDataAndResolveUrl(const std::string& url, const std::map<std::string, std::string>& existingHeaders = {});
      
      // Key Conversion Helpers
      static std::map<std::string, std::string> ParseHeaderKeys(const std::string& headerValue);
      static std::map<std::string, std::string> ParseAddHeaders(const std::string& headerValue);
      static std::string Base64urlToHex(const std::string& input);
      static std::string HexToBase64url(const std::string& hex);
      
      // Generate inputstream.adaptive clearkey JSON from KID:Key map
      static std::string GenerateClearkeyJson(const std::map<std::string, std::string>& keys);
    };
  } // namespace utilities
} // namespace iptvsimple
