/*
 *  Copyright (C) 2005-2021 Team Kodi (https://kodi.tv)
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSE.md for more information.
 */

#pragma once

#include <map>
#include <string>
#include <vector>

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

    /**
     * Result of a PHP-proxy resolution (302 redirect + optional VIP headers).
     */
    struct PhpRedirectInfo
    {
      std::string finalUrl;                          ///< MPD URL from Location header
      std::map<std::string, std::string> clearKeys;  ///< KID(hex)->KEY(hex) pairs from x-vip-clearkey
      std::map<std::string, std::string> addHeaders; ///< headers from x-vip-addheader
      bool resolved = false;                         ///< true if a 302 was actually found
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

      /**
       * Call a PHP URL (or any dynamic URL), follow the 302 redirect and
       * extract x-vip-clearkey / x-vip-addheader response headers.
       */
      static PhpRedirectInfo FetchPhpRedirectInfo(const std::string& phpUrl);

      /**
       * Convert a 32-char lowercase hex string (16 bytes) to Base64url without padding.
       * Used to build the inputstream.adaptive.drm JSON payload.
       */
      static std::string HexToBase64Url(const std::string& hex);

    private:
      static std::string Base64UrlToHex(const std::string& input);
      static std::map<std::string, std::string> ParseClearKeyHeader(const std::string& headerValue);
      static std::map<std::string, std::string> ParseAddHeader(const std::string& headerValue);
    };
  } // namespace utilities
} // namespace iptvsimple
