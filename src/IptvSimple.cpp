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

#include <ctime>
#include <chrono>
#include <sstream>

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
    {
      Logger::Log(LEVEL_DEBUG, "%s - Refreshing Channels, Grous and EPG at minute interval: %d", __func__, m_settings->GetM3URefreshIntervalMins());
      m_reloadChannelsGroupsAndEPG = true;
    }

    if (m_settings->GetM3URefreshMode() == RefreshMode::ONCE_PER_DAY &&
        lastRefreshHour != timeInfo.tm_hour && timeInfo.tm_hour == m_settings->GetM3URefreshHour())
    {
      Logger::Log(LEVEL_DEBUG, "%s - Refreshing Channels, Grous and EPG at hour of day: %d", __func__, m_settings->GetM3URefreshHour());
      m_reloadChannelsGroupsAndEPG = true;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_running && m_reloadChannelsGroupsAndEPG)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(1000));
      Logger::Log(LEVEL_DEBUG, "%s - Reloading Channels, Groups and EPG", __func__);
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
// Helper: if the URL contains "dazn-token" cut everything after ".mpd"
// ---------------------------------------------------------------------------
static std::string TrimAfterMpd(const std::string& url)
{
  std::string lower = url;
  std::transform(lower.begin(), lower.end(), lower.begin(),
                 [](unsigned char c){ return static_cast<char>(std::tolower(c)); });

  if (lower.find("dazn-token") == std::string::npos)
    return url;

  const size_t mpdPos = lower.find(".mpd");
  if (mpdPos == std::string::npos)
    return url;

  const std::string trimmed = url.substr(0, mpdPos + 4);
  Logger::Log(LEVEL_INFO, "TrimAfterMpd: trimmed DAZN token from URL -> %s", trimmed.c_str());
  return trimmed;
}

// ---------------------------------------------------------------------------
// Helper: parse "Key=Value&Key2=Value2" -> map
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
    std::string value = item.substr(eq + 1);
    kodi::tools::StringUtils::Trim(key);
    kodi::tools::StringUtils::Trim(value);
    if (!key.empty())
      result[key] = value;
  }
  return result;
}

// ---------------------------------------------------------------------------
// Helper: serialise map -> "Key=Value&Key2=Value2"
// ---------------------------------------------------------------------------
static std::string SerialiseStreamHeaders(const std::map<std::string, std::string>& hdrs)
{
  std::string out;
  for (const auto& kv : hdrs)
  {
    if (!out.empty()) out += '&';
    out += kv.first + '=' + kv.second;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Build inputstream.adaptive.drm JSON for ClearKey from hex KID/KEY pairs.
//
// ISA 21.3+ format (org.w3.clearkey):
//   {"kids":["<base64url_kid1>","<base64url_kid2>"],
//    "keys":[{"kty":"oct","kid":"<base64url_kid1>","k":"<base64url_key1>"},
//            {"kty":"oct","kid":"<base64url_kid2>","k":"<base64url_key2>"}]}
//
// The property value passed to ISA is:
//   org.w3.clearkey|<json>
// ---------------------------------------------------------------------------
static std::string BuildClearKeyDrmProperty(
    const std::map<std::string, std::string>& hexKeyMap)
{
  // kids array
  std::string kidsArray;
  std::string keysArray;
  bool first = true;
  for (const auto& kv : hexKeyMap)
  {
    const std::string kidB64 = WebUtils::HexToBase64Url(kv.first);
    const std::string keyB64 = WebUtils::HexToBase64Url(kv.second);

    if (!first) { kidsArray += ','; keysArray += ','; }
    kidsArray += '"' + kidB64 + '"';
    keysArray += "{\"kty\":\"oct\",\"kid\":\"" + kidB64 + "\",\"k\":\"" + keyB64 + "\"}"; 
    first = false;
  }

  const std::string json =
      "{\"kids\":[" + kidsArray + "],\"keys\":[" + keysArray + "]}";

  return "org.w3.clearkey|" + json;
}

PVR_ERROR IptvSimple::GetChannelStreamProperties(const kodi::addon::PVRChannel& channel,
                                                  std::vector<kodi::addon::PVRStreamProperty>& properties)
{
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
    // -----------------------------------------------------------------------
    if (IsPhpUrl(streamURL))
    {
      Logger::Log(LEVEL_INFO, "%s PHP stream URL detected, resolving: %s",
                  __FUNCTION__, WebUtils::RedactUrl(streamURL).c_str());

      const PhpRedirectInfo phpInfo = WebUtils::FetchPhpRedirectInfo(streamURL);

      if (phpInfo.resolved)
      {
        // 1) Replace stream URL with resolved MPD location
        streamURL = phpInfo.finalUrl;

        // 2) DAZN: strip token garbage after .mpd
        streamURL = TrimAfterMpd(streamURL);

        // 3) ClearKey DRM via new inputstream.adaptive.drm JSON format
        //    (ISA 21.3+). PHP keys are always fresh; M3U drm_legacy is
        //    ignored entirely when PHP delivers keys.
        if (!phpInfo.clearKeys.empty())
        {
          const std::string drmValue = BuildClearKeyDrmProperty(phpInfo.clearKeys);

          Logger::Log(LEVEL_INFO, "%s setting inputstream.adaptive.drm -> [%s]",
                      __FUNCTION__, drmValue.c_str());

          m_currentChannel.AddProperty("inputstream.adaptive.drm", drmValue);

          // Remove stale drm_legacy from M3U if present - avoids conflicts
          m_currentChannel.AddProperty("inputstream.adaptive.drm_legacy", "");
        }

        // 4) Merge stream headers (M3U base + PHP overlay, PHP wins)
        if (!phpInfo.addHeaders.empty())
        {
          const std::string HDR_PROP = "inputstream.adaptive.stream_headers";
          std::map<std::string, std::string> mergedHdrs =
              ParseStreamHeaders(m_currentChannel.GetProperty(HDR_PROP));

          for (const auto& hv : phpInfo.addHeaders)
            mergedHdrs[hv.first] = hv.second;

          const std::string finalHdrStr = SerialiseStreamHeaders(mergedHdrs);
          m_currentChannel.AddProperty(HDR_PROP, finalHdrStr);

          Logger::Log(LEVEL_INFO, "%s stream_headers after merge: %s",
                      __FUNCTION__, finalHdrStr.c_str());
        }
        else
        {
          const std::string existingHdrs =
              m_currentChannel.GetProperty("inputstream.adaptive.stream_headers");
          Logger::Log(LEVEL_INFO, "%s stream_headers (M3U only, no PHP addheader): %s",
                      __FUNCTION__, existingHdrs.empty() ? "(none)" : existingHdrs.c_str());
        }

        Logger::Log(LEVEL_INFO, "%s PHP resolution complete -> final MPD: %s",
                    __FUNCTION__, WebUtils::RedactUrl(streamURL).c_str());
      }
      else
      {
        Logger::Log(LEVEL_WARNING, "%s PHP resolution failed, using original URL", __FUNCTION__);
      }
    }
    // -----------------------------------------------------------------------

    streamURL = StreamUtils::WebStreamExtractor(streamURL, m_currentChannel);
    StreamUtils::SetAllStreamProperties(properties, m_currentChannel, streamURL, catchupUrl.empty(), catchupProperties, m_settings);

    Logger::Log(LogLevel::LEVEL_INFO, "%s - Live %s URL: %s", __FUNCTION__,
                catchupUrl.empty() ? "Stream" : "Catchup",
                WebUtils::RedactUrl(streamURL).c_str());

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

PVR_ERROR IptvSimple::GetChannelGroupMembers(const kodi::addon::PVRChannelGroup& group,
                                              kodi::addon::PVRChannelGroupMembersResultSet& results)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  return m_channelGroups.GetChannelGroupMembers(group, results);
}

/***************************************************************************
 * EPG
 **************************************************************************/

PVR_ERROR IptvSimple::GetEPGForChannel(int channelUid, time_t start, time_t end,
                                        kodi::addon::PVREPGTagsResultSet& results)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  return m_epg.GetEPGForChannel(channelUid, start, end, results);
}

PVR_ERROR IptvSimple::GetEPGTagStreamProperties(const kodi::addon::PVREPGTag& tag,
                                                 std::vector<kodi::addon::PVRStreamProperty>& properties)
{
  Logger::Log(LEVEL_DEBUG, "%s - Tag startTime: %ld \tendTime: %ld", __FUNCTION__, tag.GetStartTime(), tag.GetEndTime());

  if (GetChannel(static_cast<int>(tag.GetUniqueChannelId()), m_currentChannel))
  {
    Logger::Log(LEVEL_DEBUG, "%s - GetPlayEpgAsLive is %s", __FUNCTION__,
                m_settings->CatchupPlayEpgAsLive() ? "enabled" : "disabled");

    std::map<std::string, std::string> catchupProperties;
    if (m_settings->CatchupPlayEpgAsLive() &&
        (m_currentChannel.CatchupSupportsTimeshifting() ||
         m_currentChannel.GetCatchupMode() == CatchupMode::VOD))
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
      StreamUtils::SetAllStreamProperties(properties, m_currentChannel, catchupUrl, false,
                                          catchupProperties, m_settings);
      Logger::Log(LEVEL_INFO, "%s - EPG Catchup URL: %s", __FUNCTION__,
                  WebUtils::RedactUrl(catchupUrl).c_str());
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

PVR_ERROR IptvSimple::GetRecordingStreamProperties(const kodi::addon::PVRRecording& recording,
                                                    std::vector<kodi::addon::PVRStreamProperty>& properties)
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
 * InstanceSettings
 **************************************************************************/

ADDON_STATUS IptvSimple::SetInstanceSetting(const std::string& settingName,
                                             const kodi::addon::CSettingValue& settingValue)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  if (!m_reloadChannelsGroupsAndEPG)
    m_reloadChannelsGroupsAndEPG = true;
  return m_settings->SetSetting(settingName, settingValue);
}
