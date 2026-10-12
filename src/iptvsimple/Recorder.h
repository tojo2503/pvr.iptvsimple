/*
 *  Copyright (C) 2026 tojo2503
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSE.md for more information.
 */

#pragma once

// Client for the recording server ("Aufnahmedienst", HTTP/JSON, separate project).
// The server records, decrypts and stores; this class maps its JSON API onto
// Kodi timers and recordings. The server is the single source of truth, the
// add-on keeps no recording state of its own.

#include "InstanceSettings.h"
#include "utilities/Json.h"

#include <ctime>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <kodi/addon-instance/pvr/Recordings.h>
#include <kodi/addon-instance/pvr/Stream.h>
#include <kodi/addon-instance/pvr/Timers.h>

namespace iptvsimple
{
  // Channel data the server needs to record a channel
  struct RecorderChannel
  {
    int uniqueId = -1;
    std::string name;
    std::string streamUrl;
    std::string tvgId;
  };

  class ATTR_DLL_LOCAL Recorder
  {
  public:
    static constexpr unsigned int TIMER_TYPE_EPG = 1;
    static constexpr unsigned int TIMER_TYPE_MANUAL = 2;
    static constexpr unsigned int TIMER_TYPE_SERIES = 3;
    static constexpr unsigned int TIMER_TYPE_SERIES_CHILD = 4;
    // Rules and single timers share Kodi's client index space
    static constexpr unsigned int RULE_INDEX_OFFSET = 1000000;
    static constexpr const char* RECORDING_ID_PREFIX = "aufnahme-";

    explicit Recorder(std::shared_ptr<iptvsimple::InstanceSettings>& settings);

    bool IsEnabled() const;
    std::string GetBaseUrl() const;

    // Returns true if the server reports a change since the last call
    bool CheckForChanges();
    bool IsReachable() const { return m_reachable; }

    void GetTimerTypes(std::vector<kodi::addon::PVRTimerType>& types) const;

    // Channel lookups are done by the caller (IptvSimple), which owns the channel list
    using ChannelByUid = std::function<bool(int uid, RecorderChannel& channel)>;
    using ChannelByUrl = std::function<bool(const std::string& url, RecorderChannel& channel)>;

    PVR_ERROR GetTimers(kodi::addon::PVRTimersResultSet& results, const ChannelByUrl& channelByUrl);
    PVR_ERROR GetTimersAmount(int& amount);
    PVR_ERROR AddTimer(const kodi::addon::PVRTimer& timer, const ChannelByUid& channelByUid);
    PVR_ERROR UpdateTimer(const kodi::addon::PVRTimer& timer, const ChannelByUid& channelByUid);
    PVR_ERROR DeleteTimer(const kodi::addon::PVRTimer& timer);

    PVR_ERROR GetRecordings(std::vector<kodi::addon::PVRRecording>& recordings, const ChannelByUrl& channelByUrl);
    static bool IsRecorderRecording(const std::string& recordingId);
    PVR_ERROR GetRecordingStreamProperties(const kodi::addon::PVRRecording& recording,
                                           std::vector<kodi::addon::PVRStreamProperty>& properties);
    PVR_ERROR DeleteRecording(const kodi::addon::PVRRecording& recording);
    PVR_ERROR SetRecordingPlayCount(const kodi::addon::PVRRecording& recording, int count);
    PVR_ERROR SetRecordingLastPlayedPosition(const kodi::addon::PVRRecording& recording, int position);
    PVR_ERROR GetRecordingLastPlayedPosition(const kodi::addon::PVRRecording& recording, int& position);

  private:
    // HTTP request to the server. body is JSON (may be empty). Returns false on
    // transport or server error; error holds a message for the user.
    bool Request(const std::string& method, const std::string& path, const std::string& body,
                 utilities::JsonValue& response, std::string& error) const;
    PVR_ERROR Fail(const std::string& action, const std::string& error) const;
    static std::string RecordingServerId(const std::string& recordingId);

    std::shared_ptr<iptvsimple::InstanceSettings> m_settings;
    long long m_lastChange = -1;
    bool m_reachable = false;
    std::mutex m_mutex;
  };
} // namespace iptvsimple
