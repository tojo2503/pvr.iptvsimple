/*
 *  Copyright (C) 2005-2021 Team Kodi (https://kodi.tv)
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSE.md for more information.
 */

#include "IptvSimple.h"

#include "iptvsimple/InstanceSettings.h"
#include "iptvsimple/utilities/Logger.h"
#include "iptvsimple/utilities/TimeUtils.h"
#include "iptvsimple/utilities/WebUtils.h"

#include <algorithm>
#include <ctime>
#include <chrono>
#include <sstream>
#include <thread>

#include <kodi/tools/StringUtils.h>

using namespace iptvsimple;
using namespace iptvsimple::data;
using namespace iptvsimple::utilities;
using namespace kodi::tools;

IptvSimple::IptvSimple(const kodi::addon::IInstanceInfo& instance) : iptvsimple::IConnectionListener(instance), m_settings(new InstanceSettings(*this, instance))
{
  m_channels.Clear();
  m_channelGroups.Clear();
  m_providers.Clear();
  m_epg.Clear();
  m_media.Clear();
  connectionManager = new ConnectionManager(*this, m_settings);
}

IptvSimple::~IptvSimple()
{
  Logger::Log(LEVEL_DEBUG, "%s Stopping update thread...", __FUNCTION__);
  m_running = false;
  if (m_thread.joinable())
    m_thread.join();

  std::lock_guard<std::mutex> lock(m_mutex);
  m_channels.Clear();
  m_channelGroups.Clear();
  m_providers.Clear();
  m_epg.Clear();

  if (connectionManager)
    connectionManager->Stop();
  delete connectionManager;
}

/* **************************************************************************
 * Connection
 * *************************************************************************/

void IptvSimple::ConnectionLost()
{
  Logger::Log(LEVEL_INFO, "%s Could not validiate M3U after startup, but ignoring as startup is all we care about.", __func__);
}

void IptvSimple::ConnectionEstablished()
{
  m_channels.Init();
  m_channelGroups.Init();
  m_providers.Init();
  m_playlistLoader.Init();
  if (!m_playlistLoader.LoadPlayList())
  {
    m_channels.ChannelsLoadFailed();
    m_channelGroups.ChannelGroupsLoadFailed();
  }
  m_epg.Init(EpgMaxPastDays(), EpgMaxFutureDays());

  kodi::Log(ADDON_LOG_INFO, "%s Starting separate client update thread...", __FUNCTION__);

  m_running = true;
  m_thread = std::thread([&] { Process(); });
}

bool IptvSimple::Initialise()
{
  std::lock_guard<std::mutex> lock(m_mutex);
  connectionManager->Start();
  return true;
}

PVR_ERROR IptvSimple::OnSystemSleep()
{
  connectionManager->OnSleep();
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR IptvSimple::OnSystemWake()
{
  connectionManager->OnWake();
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR IptvSimple::GetCapabilities(kodi::addon::PVRCapabilities& capabilities)
{
  capabilities.SetSupportsEPG(true);
  capabilities.SetSupportsTV(true);
  capabilities.SetSupportsRadio(true);
  capabilities.SetSupportsChannelGroups(true);
  capabilities.SetSupportsProviders(true);
  capabilities.SetSupportsRecordingsRename(false);
  capabilities.SetSupportsRecordingsLifetimeChange(false);
  capabilities.SetSupportsDescrambleInfo(false);
  capabilities.SetSupportsRecordings(true);
  capabilities.SetSupportsRecordingsDelete(false);

  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR IptvSimple::GetBackendName(std::string& name)
{
  name = "IPTV Simple";
  return PVR_ERROR_NO_ERROR;
}
PVR_ERROR IptvSimple::GetBackendVersion(std::string& version)
{
  version = std::string(STR(IPTV_VERSION));
  return PVR_ERROR_NO_ERROR;
}
PVR_ERROR IptvSimple::GetConnectionString(std::string& connection)
{
  connection = "connected";
  return PVR_ERROR_NO_ERROR;
}

void IptvSimple::Process()
{
  unsigned int refreshTimer = 0;
  time_t lastRefreshTimeSeconds = std::time(nullptr);
  int lastRefreshHour = m_settings->GetM3URefreshHour();

  while (m_running)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(PROCESS_LOOP_WAIT_SECS * 1000));

    time_t currentRefreshTimeSeconds = std::time(nullptr);
    std::tm timeInfo = SafeLocaltime(currentRefreshTimeSeconds);
    refreshTimer += static_cast<unsigned int>(currentRefreshTimeSeconds - lastRefreshTimeSeconds);
    lastRefreshTimeSeconds = currentRefreshTimeSeconds;

    if (m_settings->GetM3URefreshMode() == RefreshMode::REPEATED_REFRESH &&
        refreshTimer >= (m_settings->GetM3URefreshIntervalMins() * 60))
      m_reloadChannelsGroupsAndEPG = true;

    if (m_settings->GetM3URefreshMode() == RefreshMode::ONCE_PER_DAY &&
        lastRefreshHour != timeInfo.tm_hour && timeInfo.tm_hour == m_settings->GetM3URefreshHour())
      m_reloadChannelsGroupsAndEPG = true;

    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_running && m_reloadChannelsGroupsAndEPG)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(1000));
      m_settings->ReloadAddonInstanceSettings();
      m_playlistLoader.ReloadPlayList();
      m_epg.ReloadEPG();
      m_reloadChannelsGroupsAndEPG = false;
      refreshTimer = 0;
    }
    lastRefreshHour = timeInfo.tm_hour;
  }
}

/***************************************************************************
 * Providers
 **************************************************************************/

PVR_ERROR IptvSimple::GetProvidersAmount(int& amount)
{
  amount = m_providers.GetNumProviders();
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR IptvSimple::GetProviders(kodi::addon::PVRProvidersResultSet& results)
{
  std::vector<kodi::addon::PVRProvider> providers;
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_providers.GetProviders(providers);
  }
  Logger::Log(LEVEL_DEBUG, "%s - providers available '%d'", __func__, providers.size());
  for (const auto& provider : providers)
    results.Add(provider);
  return PVR_ERROR_NO_ERROR;
}

/***************************************************************************
 * Channels
 **************************************************************************/

PVR_ERROR IptvSimple::GetChannelsAmount(int& amount)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  amount = m_channels.GetChannelsAmount();
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR IptvSimple::GetChannels(bool radio, kodi::addon::PVRChannelsResultSet& results)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  return m_channels.GetChannels(results, radio);
}

// ---------------------------------------------------------------------------
// Helper: does a URL end with ".php" (case-insensitive, ignores query string)?
// ---------------------------------------------------------------------------
static bool IsPhpUrl(const std::string& url)
{
  std::string path = url;
  const size_t qPos = path.find('?');
  if (qPos != std::string::npos)
    path = path.substr(0, qPos);
  if (path.size() < 4) return false;
  std::string ext = path.substr(path.size() - 4);
  for (char& c : ext) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
  return ext == ".php";
}

// ---------------------------------------------------------------------------
// Helper: append ?_iptvcb=<ms> or &_iptvcb=<ms> to a URL so that
// inputstream.adaptive treats every channel-open as a unique resource,
// forcing a full manifest re-fetch and fresh DRM/decoder init.
// ---------------------------------------------------------------------------
static std::string AppendCacheBuster(const std::string& url)
{
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count();
  const char sep = (url.find('?') == std::string::npos) ? '?' : '&';
  return url + sep + "_iptvcb=" + std::to_string(ms);
}

// ---------------------------------------------------------------------------
// Helper: parse "Key=UrlEncodedValue&Key2=UrlEncodedValue2" -> map
//
// Values are URL-decoded on read so that the internal map always holds the
// raw (unencoded) header values.  This is the counterpart of
// SerialiseStreamHeaders which URL-encodes values on write.
// ---------------------------------------------------------------------------
static std::map<std::string, std::string> ParseStreamHeaders(const std::string& hdrs)
{
  std::map<std::string, std::string> result;
  if (hdrs.empty()) return result;
  std::istringstream ss(hdrs);
  std::string item;
  while (std::getline(ss, item, '&'))
  {
    const size_t eq = item.find('=');
    if (eq == std::string::npos) continue;
    std::string key   = item.substr(0, eq);
    std::string value = WebUtils::UrlDecode(item.substr(eq + 1));
    kodi::tools::StringUtils::Trim(key);
    kodi::tools::StringUtils::Trim(value);
    if (!key.empty())
      result[key] = value;
  }
  return result;
}

// ---------------------------------------------------------------------------
// Helper: serialise map -> "Key=UrlEncodedValue&Key2=UrlEncodedValue2"
//
// Header values are URL-encoded so that characters like '=', '&', '"' and
// ',' that appear in values such as x-sky-signature do not break
// inputstream.adaptive's Key=Value&Key2=Value2 parser.
// ---------------------------------------------------------------------------
static std::string SerialiseStreamHeaders(const std::map<std::string, std::string>& hdrs)
{
  std::string out;
  for (const auto& kv : hdrs)
  {
    if (!out.empty()) out += '&';
    out += kv.first + '=' + WebUtils::UrlEncode(kv.second);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Helper: find a property by name in the PVRStreamProperty vector,
// merge PHP headers into its value, replace it. If not found, append it.
// ---------------------------------------------------------------------------
static void PatchStreamPropertyHeaders(
    std::vector<kodi::addon::PVRStreamProperty>& properties,
    const std::string& propName,
    const std::map<std::string, std::string>& phpHeaders)
{
  for (auto it = properties.begin(); it != properties.end(); ++it)
  {
    if (it->GetName() == propName)
    {
      auto merged = ParseStreamHeaders(it->GetValue());
      for (const auto& hv : phpHeaders)
        merged[hv.first] = hv.second;
      const std::string newVal = SerialiseStreamHeaders(merged);
      Logger::Log(LEVEL_DEBUG,
                  "PatchStreamPropertyHeaders [%s] before=[%s] after=[%s]",
                  propName.c_str(), it->GetValue().c_str(), newVal.c_str());
      properties.erase(it);
      properties.emplace_back(propName, newVal);
      return;
    }
  }
  const std::string newVal = SerialiseStreamHeaders(phpHeaders);
  Logger::Log(LEVEL_DEBUG,
              "PatchStreamPropertyHeaders [%s] (new) -> [%s]",
              propName.c_str(), newVal.c_str());
  properties.emplace_back(propName, newVal);
}

// ---------------------------------------------------------------------------
// Helper: escape a string for embedding inside a JSON "..." value.
// Handles the characters that would break the JSON structure.
// ---------------------------------------------------------------------------
static std::string JsonEscape(const std::string& s)
{
  std::string out;
  out.reserve(s.size() + 8);
  for (const char c : s)
  {
    switch (c)
    {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n";  break;
      case '\r': out += "\\r";  break;
      case '\t': out += "\\t";  break;
      default:   out += c;      break;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Build inputstream.adaptive.drm JSON for ClearKey from hex KID/KEY pairs.
//
// ISA 22 format:
//   {"org.w3.clearkey":{"license":{"keyids":{"KID_HEX":"KEY_HEX"}}}}
// ---------------------------------------------------------------------------
static std::string BuildClearKeyDrmProperty(
    const std::map<std::string, std::string>& hexKeyMap)
{
  std::string keyidsJson;
  bool first = true;
  for (const auto& kv : hexKeyMap)
  {
    if (!first) keyidsJson += ',';
    keyidsJson += '"' + JsonEscape(kv.first) + "\":\"" + JsonEscape(kv.second) + '"';
    first = false;
  }
  return "{\"org.w3.clearkey\":{\"license\":{\"keyids\":{" + keyidsJson + "}}}}";
}

// ---------------------------------------------------------------------------
// Build inputstream.adaptive.drm JSON for Widevine.
//
// ISA 22 format (no extra headers):
//   {"com.widevine.alpha":{"license":{"server_url":"https://..."}}}
//
// ISA 22 format (with req_headers from x-vip-l1):
//   {"com.widevine.alpha":{"license":{"server_url":"https://...",
//     "req_headers":"Key=UrlEncodedValue&Key2=UrlEncodedValue2"}}}
//
// IMPORTANT: req_headers must be a flat URL-encoded STRING, not a JSON object.
// ISA 22 parses it as Key=UrlEncodedValue&Key2=UrlEncodedValue2 internally.
// Using a JSON object here causes ISA to silently ignore the headers.
//
// licenceHeaders come exclusively from x-vip-l1 - NOT from x-vip-addheader.
// ---------------------------------------------------------------------------
static std::string BuildWidevineDrmProperty(
    const std::string& licenceUrl,
    const std::map<std::string, std::string>& licenceHeaders)
{
  std::string reqHeadersJson;
  if (!licenceHeaders.empty())
  {
    // Build URL-encoded Key=Value&Key2=Value2 string, then embed as JSON string value
    std::string headersStr;
    bool first = true;
    for (const auto& kv : licenceHeaders)
    {
      if (!first) headersStr += '&';
      headersStr += WebUtils::UrlEncode(kv.first) + '=' + WebUtils::UrlEncode(kv.second);
      first = false;
    }
    // headersStr itself does not need JsonEscape since UrlEncode produces only
    // alnum, '-', '_', '.', '~', '%' -- none of which need JSON escaping.
    reqHeadersJson = ",\"req_headers\":\"" + headersStr + '"';
  }
  return "{\"com.widevine.alpha\":{\"license\":{\"server_url\":\"" +
         JsonEscape(licenceUrl) + '"' + reqHeadersJson + "}}}";
}

PVR_ERROR IptvSimple::GetChannelStreamProperties(const kodi::addon::PVRChannel& channel, PVR_SOURCE source, std::vector<kodi::addon::PVRStreamProperty>& properties)
{
  // Ensure no stale properties from a previous channel switch remain.
  // Kodi may reuse the vector across PVR channel switches without clearing it.
  properties.clear();

  if (GetChannel(channel, m_currentChannel))
  {
    std::string streamURL = m_currentChannel.GetStreamURL();

    m_catchupController.ResetCatchupState();

    std::map<std::string, std::string> catchupProperties;
    m_catchupController.ProcessChannelForPlayback(m_currentChannel, catchupProperties);

    const std::string catchupUrl = m_catchupController.GetCatchupUrl(m_currentChannel);
    if (!catchupUrl.empty())
      streamURL = catchupUrl;
    else
      streamURL = m_catchupController.ProcessStreamUrl(m_currentChannel);

    // -----------------------------------------------------------------------
    // PHP-proxy resolution
    //
    // Header routing:
    //   x-vip-licenceurl  -> Widevine server_url in DRM JSON
    //   x-vip-l1          -> Widevine req_headers in DRM JSON (licence call only)
    //   x-vip-addheader   -> stream_headers + manifest_headers (segments + MPD)
    //   x-vip-clearkey    -> ClearKey DRM JSON
    //
    // x-vip-addheader does NOT go into Widevine req_headers.
    // x-vip-l1 does NOT go into stream_headers / manifest_headers.
    // -----------------------------------------------------------------------
    std::map<std::string, std::string> phpAddHeaders;
    bool phpDrmSet = false;

    if (IsPhpUrl(streamURL))
    {
      // ---------------------------------------------------------------------
      // Wait for StreamClosed() to confirm the previous player has been torn
      // down before issuing the PHP HTTP request.  This prevents the Android
      // MediaCodec InstanceGuard from still being held by the old stream when
      // the new codec tries to open, which would cause "InstanceGuard locked"
      // -> black/encrypted video with audio only on cross-provider switches.
      //
      // Kodi calls GetChannelStreamProperties *before* calling StreamClosed
      // on the previous stream.  For fast same-provider PHP responses the
      // teardown completes before SetAllStreamProperties returns, but for
      // slow cross-provider responses (~10s) it does not.  We poll
      // m_streamActive (cleared by StreamClosed) for up to
      // MAX_STREAM_CLOSE_WAIT_MS before proceeding.
      // ---------------------------------------------------------------------
      if (m_streamActive.load())
      {
        Logger::Log(LEVEL_INFO,
                    "%s Previous stream still active, waiting up to %d ms for StreamClosed() before PHP request",
                    __FUNCTION__, MAX_STREAM_CLOSE_WAIT_MS);

        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(MAX_STREAM_CLOSE_WAIT_MS);
        while (m_streamActive.load() &&
               std::chrono::steady_clock::now() < deadline)
        {
          std::this_thread::sleep_for(std::chrono::milliseconds(STREAM_CLOSE_POLL_MS));
        }

        if (m_streamActive.load())
          Logger::Log(LEVEL_WARNING,
                      "%s StreamClosed() not received within %d ms, proceeding anyway",
                      __FUNCTION__, MAX_STREAM_CLOSE_WAIT_MS);
        else
          Logger::Log(LEVEL_INFO,
                      "%s StreamClosed() received, proceeding with PHP request",
                      __FUNCTION__);
      }

      // Mark this channel-open as active *after* the wait so that the next
      // switch can observe that a stream is now in progress.
      m_streamActive.store(true);

      Logger::Log(LEVEL_INFO, "%s PHP stream URL detected, resolving: %s",
                  __FUNCTION__, WebUtils::RedactUrl(streamURL).c_str());

      const PhpRedirectInfo phpInfo = WebUtils::FetchPhpRedirectInfo(streamURL);

      if (phpInfo.resolved)
      {
        // Evict the stale StreamManager cache entry that was keyed on the
        // original .php URL.
        m_streamManager.RemoveEntry(streamURL);

        // 1) Replace stream URL with resolved MPD location, then append a
        //    millisecond cache-buster so inputstream.adaptive always treats
        //    this as a new resource -> forces a clean DRM/decoder init on
        //    every channel switch without needing a full player stop/start.
        streamURL = AppendCacheBuster(phpInfo.finalUrl);
        Logger::Log(LEVEL_DEBUG, "%s Cache-busted MPD URL: %s",
                    __FUNCTION__, WebUtils::RedactUrl(streamURL).c_str());

        // 2a) ClearKey DRM (x-vip-clearkey)
        if (!phpInfo.clearKeys.empty())
        {
          const std::string drmValue = BuildClearKeyDrmProperty(phpInfo.clearKeys);
          Logger::Log(LEVEL_INFO, "%s setting ClearKey DRM -> [%s]", __FUNCTION__, drmValue.c_str());
          m_currentChannel.SetProperty("inputstream.adaptive.drm", drmValue);
          phpDrmSet = true;
        }

        // 2b) Widevine DRM (x-vip-licenceurl) - mutually exclusive with ClearKey.
        //     req_headers come from x-vip-l1 only.
        if (!phpInfo.licenceUrl.empty() && !phpDrmSet)
        {
          Logger::Log(LEVEL_INFO, "%s setting Widevine DRM, server_url=[%s], %zu x-vip-l1 header(s)",
                      __FUNCTION__, phpInfo.licenceUrl.c_str(), phpInfo.licenceHeaders.size());
          for (const auto& hv : phpInfo.licenceHeaders)
            Logger::Log(LEVEL_DEBUG, "%s   Widevine req_header [%s] = [%s]",
                        __FUNCTION__, hv.first.c_str(), hv.second.c_str());

          const std::string drmValue = BuildWidevineDrmProperty(phpInfo.licenceUrl, phpInfo.licenceHeaders);
          Logger::Log(LEVEL_DEBUG, "%s   DRM JSON -> [%s]", __FUNCTION__, drmValue.c_str());
          m_currentChannel.SetProperty("inputstream.adaptive.drm", drmValue);
          phpDrmSet = true;
        }

        // 3) Save x-vip-addheader for post-patch into stream_headers + manifest_headers.
        //    These do NOT go into Widevine req_headers.
        phpAddHeaders = phpInfo.addHeaders;
        Logger::Log(LEVEL_DEBUG, "%s x-vip-addheader saved (%zu key(s)) for stream/manifest post-patch",
                    __FUNCTION__, phpAddHeaders.size());
        for (const auto& hv : phpAddHeaders)
          Logger::Log(LEVEL_DEBUG, "%s   [%s] = [%s]",
                      __FUNCTION__, hv.first.c_str(), hv.second.c_str());

        Logger::Log(LEVEL_INFO, "%s PHP resolution complete -> final MPD: %s",
                    __FUNCTION__, WebUtils::RedactUrl(streamURL).c_str());
      }
      else
      {
        Logger::Log(LEVEL_WARNING, "%s PHP resolution failed, using original URL", __FUNCTION__);
      }
    }
    else
    {
      // Non-PHP channel: mark stream active immediately (no wait needed).
      m_streamActive.store(true);
    }
    // -----------------------------------------------------------------------

    streamURL = StreamUtils::WebStreamExtractor(streamURL, m_currentChannel);
    StreamUtils::SetAllStreamProperties(properties, m_currentChannel, streamURL, catchupUrl.empty(), catchupProperties, m_settings);

    // -----------------------------------------------------------------------
    // Post-patch: merge x-vip-addheader into stream_headers + manifest_headers.
    // Values are URL-encoded by SerialiseStreamHeaders so that header values
    // containing '=', '&', '"' or ',' (e.g. x-sky-signature) are passed
    // through ISA's Key=Value&Key2=Value2 parser without corruption.
    // x-vip-l1 (licence-only headers) is NOT applied here.
    // -----------------------------------------------------------------------
    if (!phpAddHeaders.empty())
    {
      const std::string STREAM_HDR   = "inputstream.adaptive.stream_headers";
      const std::string MANIFEST_HDR = "inputstream.adaptive.manifest_headers";

      Logger::Log(LEVEL_DEBUG, "%s [POST-PATCH] applying %zu x-vip-addheader header(s) to properties vector",
                  __FUNCTION__, phpAddHeaders.size());

      PatchStreamPropertyHeaders(properties, STREAM_HDR,   phpAddHeaders);
      PatchStreamPropertyHeaders(properties, MANIFEST_HDR, phpAddHeaders);

      for (const auto& p : properties)
      {
        if (p.GetName() == STREAM_HDR || p.GetName() == MANIFEST_HDR)
          Logger::Log(LEVEL_DEBUG, "%s [POST-PATCH] confirmed [%s] = [%s]",
                      __FUNCTION__, p.GetName().c_str(), p.GetValue().c_str());
      }
    }

    // -----------------------------------------------------------------------
    // Post-process: strip legacy DRM properties if PHP set .drm
    // -----------------------------------------------------------------------
    if (phpDrmSet)
    {
      properties.erase(
        std::remove_if(properties.begin(), properties.end(),
          [](const kodi::addon::PVRStreamProperty& p)
          {
            const std::string& n = p.GetName();
            return n == "inputstream.adaptive.drm_legacy" ||
                   n == "inputstream.adaptive.license_type" ||
                   n == "inputstream.adaptive.license_key";
          }),
        properties.end());
      Logger::Log(LEVEL_DEBUG, "%s Stripped legacy DRM properties", __FUNCTION__);
    }
    // -----------------------------------------------------------------------

    Logger::Log(LogLevel::LEVEL_INFO, "%s - Live %s URL: %s",
                __FUNCTION__,
                catchupUrl.empty() ? "Stream" : "Catchup",
                WebUtils::RedactUrl(streamURL).c_str());

    // Dump all final properties so we can verify what ISA receives.
    Logger::Log(LEVEL_INFO, "%s [FINAL] %zu properties for ISA:",
                __FUNCTION__, properties.size());
    for (const auto& p : properties)
      Logger::Log(LEVEL_INFO, "%s [FINAL]   [%s] = [%s]",
                  __FUNCTION__, p.GetName().c_str(), p.GetValue().c_str());

    return PVR_ERROR_NO_ERROR;
  }

  return PVR_ERROR_SERVER_ERROR;
}

bool IptvSimple::GetChannel(const kodi::addon::PVRChannel& channel, Channel& myChannel)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  return m_channels.GetChannel(channel, myChannel);
}

bool IptvSimple::GetChannel(unsigned int uniqueChannelId, iptvsimple::data::Channel& myChannel)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  return m_channels.GetChannel(uniqueChannelId, myChannel);
}

/***************************************************************************
 * Channel Groups
 **************************************************************************/

PVR_ERROR IptvSimple::GetChannelGroupsAmount(int& amount)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  amount = m_channelGroups.GetChannelGroupsAmount();
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR IptvSimple::GetChannelGroups(bool radio, kodi::addon::PVRChannelGroupsResultSet& results)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  return m_channelGroups.GetChannelGroups(results, radio);
}

PVR_ERROR IptvSimple::GetChannelGroupMembers(const kodi::addon::PVRChannelGroup& group, kodi::addon::PVRChannelGroupMembersResultSet& results)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  return m_channelGroups.GetChannelGroupMembers(group, results);
}

/***************************************************************************
 * EPG
 **************************************************************************/

PVR_ERROR IptvSimple::GetEPGForChannel(int channelUid, time_t start, time_t end, kodi::addon::PVREPGTagsResultSet& results)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  return m_epg.GetEPGForChannel(channelUid, start, end, results);
}

PVR_ERROR IptvSimple::GetEPGTagStreamProperties(const kodi::addon::PVREPGTag& tag, std::vector<kodi::addon::PVRStreamProperty>& properties)
{
  Logger::Log(LEVEL_DEBUG, "%s - Tag startTime: %ld \tendTime: %ld", __FUNCTION__, tag.GetStartTime(), tag.GetEndTime());

  if (GetChannel(static_cast<int>(tag.GetUniqueChannelId()), m_currentChannel))
  {
    Logger::Log(LEVEL_DEBUG, "%s - GetPlayEpgAsLive is %s", __FUNCTION__, m_settings->CatchupPlayEpgAsLive() ? "enabled" : "disabled");

    std::map<std::string, std::string> catchupProperties;
    if (m_settings->CatchupPlayEpgAsLive() && (m_currentChannel.CatchupSupportsTimeshifting() || m_currentChannel.GetCatchupMode() == CatchupMode::VOD))
    {
      m_catchupController.ProcessEPGTagForTimeshiftedPlayback(tag, m_currentChannel, catchupProperties);
    }
    else
    {
      m_catchupController.ResetCatchupState();
      m_catchupController.ProcessEPGTagForVideoPlayback(tag, m_currentChannel, catchupProperties);
    }

    const std::string catchupUrl = m_catchupController.GetCatchupUrl(m_currentChannel);
    if (!catchupUrl.empty())
    {
      StreamUtils::SetAllStreamProperties(properties, m_currentChannel, catchupUrl, false, catchupProperties, m_settings);
      Logger::Log(LEVEL_INFO, "%s - EPG Catchup URL: %s", __FUNCTION__, WebUtils::RedactUrl(catchupUrl).c_str());
      return PVR_ERROR_NO_ERROR;
    }
  }

  return PVR_ERROR_FAILED;
}

PVR_ERROR IptvSimple::IsEPGTagPlayable(const kodi::addon::PVREPGTag& tag, bool& bIsPlayable)
{
  if (!m_settings->IsCatchupEnabled())
    return PVR_ERROR_NOT_IMPLEMENTED;

  const time_t now = std::time(nullptr);
  Channel channel{m_settings};

  bIsPlayable = GetChannel(static_cast<int>(tag.GetUniqueChannelId()), channel) &&
                m_settings->IsCatchupEnabled() && channel.IsCatchupSupported();

  if (channel.IgnoreCatchupDays())
  {
    bool hasCatchupId = false;
    EpgEntry* epgEntry = m_catchupController.GetEPGEntry(channel, tag.GetStartTime());
    if (epgEntry)
      hasCatchupId = !epgEntry->GetCatchupId().empty();
    bIsPlayable = bIsPlayable && hasCatchupId;
  }
  else
  {
    bIsPlayable = bIsPlayable &&
                  tag.GetStartTime() < now &&
                  tag.GetStartTime() >= (now - static_cast<time_t>(channel.GetCatchupDaysInSeconds())) &&
                  (!m_settings->CatchupOnlyOnFinishedProgrammes() || tag.GetEndTime() < now);
  }

  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR IptvSimple::SetEPGMaxPastDays(int epgMaxPastDays)
{
  m_epg.SetEPGMaxPastDays(epgMaxPastDays);
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR IptvSimple::SetEPGMaxFutureDays(int epgMaxFutureDays)
{
  m_epg.SetEPGMaxFutureDays(epgMaxFutureDays);
  return PVR_ERROR_NO_ERROR;
}

/***************************************************************************
 * Media
 **************************************************************************/

PVR_ERROR IptvSimple::GetRecordingsAmount(bool deleted, int& amount)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  if (deleted)
    amount = 0;
  else
    amount = m_media.GetNumMedia();
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR IptvSimple::GetRecordings(bool deleted, kodi::addon::PVRRecordingsResultSet& results)
{
  if (!deleted)
  {
    std::vector<kodi::addon::PVRRecording> media;
    {
      std::lock_guard<std::mutex> lock(m_mutex);
      m_media.GetMedia(media);
    }
    for (const auto& mediaTag : media)
      results.Add(mediaTag);
    Logger::Log(LEVEL_DEBUG, "%s - media available '%d'", __func__, media.size());
  }
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR IptvSimple::GetRecordingStreamProperties(const kodi::addon::PVRRecording& recording, std::vector<kodi::addon::PVRStreamProperty>& properties)
{
  auto mediaEntry = m_media.GetMediaEntry(recording);
  std::string url = m_media.GetMediaEntryURL(recording);

  if (!mediaEntry.GetMediaEntryId().empty() && !url.empty())
  {
    url = StreamUtils::WebStreamExtractor(url, mediaEntry);
    StreamUtils::SetAllStreamProperties(properties, mediaEntry, url, m_settings);
    return PVR_ERROR_NO_ERROR;
  }

  return PVR_ERROR_SERVER_ERROR;
}

/***************************************************************************
 * Signal Status
 **************************************************************************/

PVR_ERROR IptvSimple::GetSignalStatus(int channelUid, kodi::addon::PVRSignalStatus& signalStatus)
{
  signalStatus.SetAdapterName("IPTV Simple Adapter 1");
  signalStatus.SetAdapterStatus("OK");
  return PVR_ERROR_NO_ERROR;
}

/***************************************************************************
 * Stream State
 **************************************************************************/

PVR_ERROR IptvSimple::StreamClosed()
{
  Logger::Log(LEVEL_INFO, "%s - Stream Closed", __FUNCTION__);
  // Signal that the previous player/decoder session has been torn down.
  // GetChannelStreamProperties waits on this flag (via m_streamActive) before
  // issuing a PHP HTTP request, to ensure the MediaCodec InstanceGuard has
  // been released before we attempt to open the new video codec.
  m_streamActive.store(false);
  return PVR_ERROR_NO_ERROR;
}

/***************************************************************************
 * InstanceSettings
 **************************************************************************/

ADDON_STATUS IptvSimple::SetInstanceSetting(const std::string& settingName, const kodi::addon::CSettingValue& settingValue)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  if (!m_reloadChannelsGroupsAndEPG)
    m_reloadChannelsGroupsAndEPG = true;

  return m_settings->SetSetting(settingName, settingValue);
}
