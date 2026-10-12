/*
 *  Copyright (C) 2026 tojo2503
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSE.md for more information.
 */

#include "Recorder.h"

#include "utilities/Logger.h"

#include <kodi/Filesystem.h>
#include <kodi/General.h>
#include <kodi/tools/StringUtils.h>

using namespace iptvsimple;
using namespace iptvsimple::utilities;
using kodi::tools::StringUtils;

namespace
{
  std::string Base64Encode(const std::string& in)
  {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, bits = -6;
    for (unsigned char c : in)
    {
      val = (val << 8) + c;
      bits += 8;
      while (bits >= 0)
      {
        out.push_back(tbl[(val >> bits) & 0x3F]);
        bits -= 6;
      }
    }
    if (bits > -6)
      out.push_back(tbl[((val << 8) >> (bits + 8)) & 0x3F]);
    while (out.size() % 4)
      out.push_back('=');
    return out;
  }

  PVR_TIMER_STATE StateFromServer(const std::string& status)
  {
    if (status == "geplant")
      return PVR_TIMER_STATE_SCHEDULED;
    if (status == "laeuft")
      return PVR_TIMER_STATE_RECORDING;
    if (status == "fertig")
      return PVR_TIMER_STATE_COMPLETED;
    if (status == "abgebrochen")
      return PVR_TIMER_STATE_ABORTED;
    if (status == "aus")
      return PVR_TIMER_STATE_DISABLED;
    return PVR_TIMER_STATE_ERROR;
  }

  std::string JsonField(const std::string& key, const std::string& value)
  {
    return Json::Escape(key) + ":" + Json::Escape(value);
  }

  std::string JsonField(const std::string& key, long long value)
  {
    return Json::Escape(key) + ":" + std::to_string(value);
  }
} // unnamed namespace

Recorder::Recorder(std::shared_ptr<iptvsimple::InstanceSettings>& settings) : m_settings(settings)
{
}

bool Recorder::IsEnabled() const
{
  return !m_settings->GetRecorderUrl().empty();
}

std::string Recorder::GetBaseUrl() const
{
  std::string url = m_settings->GetRecorderUrl();
  while (!url.empty() && url.back() == '/')
    url.pop_back();
  return url;
}

bool Recorder::Request(const std::string& method, const std::string& path, const std::string& body,
                       JsonValue& response, std::string& error) const
{
  error.clear();
  const std::string url = GetBaseUrl() + path;
  kodi::vfs::CFile file;
  if (!file.CURLCreate(url))
  {
    error = "Aufnahme-Server: ungültige Adresse";
    return false;
  }
  file.CURLAddOption(ADDON_CURL_OPTION_PROTOCOL, "connection-timeout", "5");
  // Read error bodies too: the server reports problems as {"fehler": "..."}
  file.CURLAddOption(ADDON_CURL_OPTION_PROTOCOL, "failonerror", "false");
  file.CURLAddOption(ADDON_CURL_OPTION_PROTOCOL, "seekable", "0");
  file.CURLAddOption(ADDON_CURL_OPTION_HEADER, "Accept", "application/json");
  if (method != "GET")
    file.CURLAddOption(ADDON_CURL_OPTION_PROTOCOL, "customrequest", method);
  if (!body.empty())
  {
    file.CURLAddOption(ADDON_CURL_OPTION_HEADER, "Content-Type", "application/json");
    file.CURLAddOption(ADDON_CURL_OPTION_PROTOCOL, "postdata", Base64Encode(body));
  }
  if (!file.CURLOpen(ADDON_READ_NO_CACHE))
  {
    error = "Aufnahme-Server nicht erreichbar";
    Logger::Log(LEVEL_ERROR, "%s - %s %s failed", __func__, method.c_str(), url.c_str());
    return false;
  }
  // Status line, e.g. "HTTP/1.1 409 Conflict"
  const std::string status = file.GetPropertyValue(ADDON_FILE_PROPERTY_RESPONSE_PROTOCOL, "");
  const size_t space = status.find(' ');
  const int code = space == std::string::npos ? 0 : std::atoi(status.c_str() + space + 1);
  std::string text;
  char buf[16384];
  ssize_t n;
  while ((n = file.Read(buf, sizeof(buf))) > 0)
    text.append(buf, static_cast<size_t>(n));
  file.Close();

  response = JsonValue();
  if (!Json::Parse(text, response))
  {
    error = "Aufnahme-Server: ungültige Antwort";
    Logger::Log(LEVEL_ERROR, "%s - %s %s: invalid JSON (%d bytes, %s)", __func__, method.c_str(), url.c_str(),
                static_cast<int>(text.size()), status.c_str());
    return false;
  }
  // Errors come as {"fehler": "..."} with a 4xx/5xx status. Timers and recordings
  // also have a "fehler" field (null or a note), so only the status decides.
  const bool failed = code >= 400 || (code == 0 && response.object.size() == 1 && response.Has("fehler"));
  if (failed)
  {
    error = response["fehler"].Str("Aufnahme-Server: Fehler " + std::to_string(code));
    Logger::Log(LEVEL_ERROR, "%s - %s %s: %s", __func__, method.c_str(), url.c_str(), error.c_str());
    return false;
  }
  return true;
}

PVR_ERROR Recorder::Fail(const std::string& action, const std::string& error) const
{
  kodi::QueueNotification(QUEUE_ERROR, action, error);
  return PVR_ERROR_REJECTED;
}

bool Recorder::CheckForChanges()
{
  if (!IsEnabled())
    return false;
  JsonValue r;
  std::string error;
  bool ok = Request("GET", "/api/aenderung", "", r, error);
  std::lock_guard<std::mutex> lock(m_mutex);
  bool wasReachable = m_reachable;
  m_reachable = ok;
  if (!ok)
    return false;
  long long n = r["n"].Int(-1);
  bool changed = n != m_lastChange || !wasReachable;
  m_lastChange = n;
  return changed;
}

void Recorder::GetTimerTypes(std::vector<kodi::addon::PVRTimerType>& types) const
{
  const uint64_t margins = PVR_TIMER_TYPE_SUPPORTS_START_MARGIN | PVR_TIMER_TYPE_SUPPORTS_END_MARGIN;

  kodi::addon::PVRTimerType epg;
  epg.SetId(TIMER_TYPE_EPG);
  epg.SetDescription("Einmalig");
  epg.SetAttributes(PVR_TIMER_TYPE_REQUIRES_EPG_TAG_ON_CREATE | PVR_TIMER_TYPE_SUPPORTS_CHANNELS |
                    PVR_TIMER_TYPE_SUPPORTS_START_TIME | PVR_TIMER_TYPE_SUPPORTS_END_TIME | margins);
  types.emplace_back(epg);

  kodi::addon::PVRTimerType manual;
  manual.SetId(TIMER_TYPE_MANUAL);
  manual.SetDescription("Manuell");
  manual.SetAttributes(PVR_TIMER_TYPE_IS_MANUAL | PVR_TIMER_TYPE_FORBIDS_EPG_TAG_ON_CREATE |
                       PVR_TIMER_TYPE_SUPPORTS_CHANNELS | PVR_TIMER_TYPE_SUPPORTS_START_TIME |
                       PVR_TIMER_TYPE_SUPPORTS_END_TIME | margins);
  types.emplace_back(manual);

  kodi::addon::PVRTimerType series;
  series.SetId(TIMER_TYPE_SERIES);
  series.SetDescription("Serie");
  series.SetAttributes(PVR_TIMER_TYPE_IS_REPEATING | PVR_TIMER_TYPE_SUPPORTS_ENABLE_DISABLE |
                       PVR_TIMER_TYPE_SUPPORTS_CHANNELS | PVR_TIMER_TYPE_SUPPORTS_ANY_CHANNEL |
                       PVR_TIMER_TYPE_SUPPORTS_TITLE_EPG_MATCH | PVR_TIMER_TYPE_SUPPORTS_FULLTEXT_EPG_MATCH |
                       PVR_TIMER_TYPE_SUPPORTS_RECORD_ONLY_NEW_EPISODES | margins);
  series.SetPreventDuplicateEpisodes({{0, "Alle Folgen"}, {1, "Nur neue Folgen"}}, 1);
  types.emplace_back(series);

  kodi::addon::PVRTimerType child;
  child.SetId(TIMER_TYPE_SERIES_CHILD);
  child.SetDescription("Serie (Folge)");
  child.SetAttributes(PVR_TIMER_TYPE_IS_READONLY | PVR_TIMER_TYPE_SUPPORTS_READONLY_DELETE |
                      PVR_TIMER_TYPE_FORBIDS_NEW_INSTANCES | PVR_TIMER_TYPE_SUPPORTS_CHANNELS |
                      PVR_TIMER_TYPE_SUPPORTS_START_TIME | PVR_TIMER_TYPE_SUPPORTS_END_TIME | margins);
  types.emplace_back(child);
}

PVR_ERROR Recorder::GetTimersAmount(int& amount)
{
  amount = 0;
  if (!IsEnabled())
    return PVR_ERROR_NO_ERROR;
  JsonValue timers, rules;
  std::string error;
  if (!Request("GET", "/api/timer", "", timers, error) || !Request("GET", "/api/regeln", "", rules, error))
    return PVR_ERROR_SERVER_ERROR;
  amount = static_cast<int>(timers.array.size() + rules.array.size());
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR Recorder::GetTimers(kodi::addon::PVRTimersResultSet& results, const ChannelByUrl& channelByUrl)
{
  if (!IsEnabled())
    return PVR_ERROR_NO_ERROR;
  JsonValue timers, rules;
  std::string error;
  if (!Request("GET", "/api/regeln", "", rules, error) || !Request("GET", "/api/timer", "", timers, error))
    return PVR_ERROR_SERVER_ERROR;

  for (const auto& r : rules.array)
  {
    kodi::addon::PVRTimer t;
    t.SetClientIndex(RULE_INDEX_OFFSET + static_cast<unsigned int>(r["id"].Int()));
    t.SetTimerType(TIMER_TYPE_SERIES);
    t.SetState(r["aktiv"].Bool(true) ? PVR_TIMER_STATE_SCHEDULED : PVR_TIMER_STATE_DISABLED);
    t.SetTitle(r["titel"].Str());
    t.SetEPGSearchString(r["titel"].Str());
    t.SetFullTextEpgSearch(r["modus"].Str() == "enthaelt");
    RecorderChannel ch;
    if (!r["sender_url"].Str().empty() && channelByUrl(r["sender_url"].Str(), ch))
      t.SetClientChannelUid(ch.uniqueId);
    else
      t.SetClientChannelUid(PVR_TIMER_ANY_CHANNEL);
    t.SetPreventDuplicateEpisodes(r["nur_neue"].Bool(true) ? 1 : 0);
    t.SetMarginStart(static_cast<unsigned int>(r["vorlauf"].Int() / 60));
    t.SetMarginEnd(static_cast<unsigned int>(r["nachlauf"].Int() / 60));
    t.SetStartAnyTime(true);
    t.SetEndAnyTime(true);
    results.Add(t);
  }

  for (const auto& j : timers.array)
  {
    kodi::addon::PVRTimer t;
    t.SetClientIndex(static_cast<unsigned int>(j["id"].Int()));
    const long long ruleId = j["regel_id"].Int(0);
    if (ruleId > 0)
    {
      t.SetTimerType(TIMER_TYPE_SERIES_CHILD);
      t.SetParentClientIndex(RULE_INDEX_OFFSET + static_cast<unsigned int>(ruleId));
    }
    else
      t.SetTimerType(j["epg_id"].IsNull() ? TIMER_TYPE_MANUAL : TIMER_TYPE_EPG);
    t.SetState(StateFromServer(j["status"].Str()));
    t.SetTitle(j["titel"].Str());
    t.SetSummary(j["beschreibung"].Str());
    const time_t start = static_cast<time_t>(j["start"].Int());
    t.SetStartTime(start);
    t.SetEndTime(static_cast<time_t>(j["ende"].Int()));
    t.SetMarginStart(static_cast<unsigned int>(j["vorlauf"].Int() / 60));
    t.SetMarginEnd(static_cast<unsigned int>(j["nachlauf"].Int() / 60));
    // pvr.iptvsimple uses the programme start as EPG broadcast id
    if (!j["epg_id"].IsNull())
      t.SetEPGUid(static_cast<unsigned int>(start));
    RecorderChannel ch;
    if (channelByUrl(j["sender_url"].Str(), ch))
      t.SetClientChannelUid(ch.uniqueId);
    else
      t.SetClientChannelUid(PVR_CHANNEL_INVALID_UID);
    results.Add(t);
  }
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR Recorder::AddTimer(const kodi::addon::PVRTimer& timer, const ChannelByUid& channelByUid)
{
  if (!IsEnabled())
    return PVR_ERROR_NOT_IMPLEMENTED;
  JsonValue r;
  std::string error;
  const long long marginStart = static_cast<long long>(timer.GetMarginStart()) * 60;
  const long long marginEnd = static_cast<long long>(timer.GetMarginEnd()) * 60;

  if (timer.GetTimerType() == TIMER_TYPE_SERIES)
  {
    std::string title = timer.GetEPGSearchString().empty() ? timer.GetTitle() : timer.GetEPGSearchString();
    std::string body = "{" + JsonField("titel", title) + "," +
                       JsonField("modus", timer.GetFullTextEpgSearch() ? "enthaelt" : "gleich") + "," +
                       JsonField("nur_neue", timer.GetPreventDuplicateEpisodes() > 0 ? 1 : 0) + "," +
                       JsonField("vorlauf", marginStart) + "," + JsonField("nachlauf", marginEnd);
    RecorderChannel ch;
    if (timer.GetClientChannelUid() != PVR_TIMER_ANY_CHANNEL && channelByUid(timer.GetClientChannelUid(), ch))
      body += "," + JsonField("sender", ch.streamUrl);
    body += "}";
    if (!Request("POST", "/api/regeln", body, r, error))
      return Fail("Serie anlegen", error);
    return PVR_ERROR_NO_ERROR;
  }

  RecorderChannel ch;
  if (!channelByUid(timer.GetClientChannelUid(), ch))
    return Fail("Aufnahme", "Sender nicht gefunden");

  std::string body = "{" + JsonField("sender", ch.streamUrl) + "," + JsonField("sender_name", ch.name) + "," +
                     JsonField("tvg_id", ch.tvgId) + "," +
                     JsonField("start", static_cast<long long>(timer.GetStartTime())) + "," +
                     JsonField("ende", static_cast<long long>(timer.GetEndTime())) + "," +
                     JsonField("vorlauf", marginStart) + "," + JsonField("nachlauf", marginEnd);
  // Manual timers carry the channel name as title; let the server take the EPG title instead
  if (!timer.GetTitle().empty() && timer.GetTitle() != ch.name)
    body += "," + JsonField("titel", timer.GetTitle());
  if (!timer.GetSummary().empty())
    body += "," + JsonField("beschreibung", timer.GetSummary());
  body += "}";
  if (!Request("POST", "/api/timer", body, r, error))
    return Fail("Aufnahme", error);
  Logger::Log(LEVEL_INFO, "%s - timer %lld for '%s' on '%s'", __func__, r["id"].Int(), r["titel"].Str().c_str(),
              ch.name.c_str());
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR Recorder::UpdateTimer(const kodi::addon::PVRTimer& timer, const ChannelByUid& channelByUid)
{
  if (!IsEnabled())
    return PVR_ERROR_NOT_IMPLEMENTED;
  JsonValue r;
  std::string error;
  const long long marginStart = static_cast<long long>(timer.GetMarginStart()) * 60;
  const long long marginEnd = static_cast<long long>(timer.GetMarginEnd()) * 60;

  if (timer.GetTimerType() == TIMER_TYPE_SERIES)
  {
    const unsigned int ruleId = timer.GetClientIndex() - RULE_INDEX_OFFSET;
    std::string title = timer.GetEPGSearchString().empty() ? timer.GetTitle() : timer.GetEPGSearchString();
    std::string sender;
    RecorderChannel ch;
    if (timer.GetClientChannelUid() != PVR_TIMER_ANY_CHANNEL && channelByUid(timer.GetClientChannelUid(), ch))
      sender = ch.streamUrl;
    std::string body = "{" + JsonField("titel", title) + "," +
                       JsonField("modus", timer.GetFullTextEpgSearch() ? "enthaelt" : "gleich") + "," +
                       JsonField("nur_neue", timer.GetPreventDuplicateEpisodes() > 0 ? 1 : 0) + "," +
                       JsonField("aktiv", timer.GetState() == PVR_TIMER_STATE_DISABLED ? 0 : 1) + "," +
                       JsonField("vorlauf", marginStart) + "," + JsonField("nachlauf", marginEnd) + "," +
                       (sender.empty() ? std::string("\"sender\":null") : JsonField("sender", sender)) + "}";
    if (!Request("PUT", "/api/regeln/" + std::to_string(ruleId), body, r, error))
      return Fail("Serie ändern", error);
    return PVR_ERROR_NO_ERROR;
  }

  std::string body = "{" + JsonField("start", static_cast<long long>(timer.GetStartTime())) + "," +
                     JsonField("ende", static_cast<long long>(timer.GetEndTime())) + "," +
                     JsonField("vorlauf", marginStart) + "," + JsonField("nachlauf", marginEnd);
  if (!timer.GetTitle().empty())
    body += "," + JsonField("titel", timer.GetTitle());
  body += "}";
  if (!Request("PUT", "/api/timer/" + std::to_string(timer.GetClientIndex()), body, r, error))
    return Fail("Aufnahme ändern", error);
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR Recorder::DeleteTimer(const kodi::addon::PVRTimer& timer)
{
  if (!IsEnabled())
    return PVR_ERROR_NOT_IMPLEMENTED;
  JsonValue r;
  std::string error;
  std::string path = timer.GetTimerType() == TIMER_TYPE_SERIES
                         ? "/api/regeln/" + std::to_string(timer.GetClientIndex() - RULE_INDEX_OFFSET)
                         : "/api/timer/" + std::to_string(timer.GetClientIndex());
  if (!Request("DELETE", path, "", r, error))
    return Fail("Löschen", error);
  return PVR_ERROR_NO_ERROR;
}

bool Recorder::IsRecorderRecording(const std::string& recordingId)
{
  return StringUtils::StartsWith(recordingId, RECORDING_ID_PREFIX);
}

std::string Recorder::RecordingServerId(const std::string& recordingId)
{
  return recordingId.substr(std::string(RECORDING_ID_PREFIX).size());
}

PVR_ERROR Recorder::GetRecordings(std::vector<kodi::addon::PVRRecording>& recordings, const ChannelByUrl& channelByUrl)
{
  if (!IsEnabled())
    return PVR_ERROR_NO_ERROR;
  JsonValue list;
  std::string error;
  if (!Request("GET", "/api/aufnahmen", "", list, error))
    return PVR_ERROR_SERVER_ERROR;
  for (const auto& a : list.array)
  {
    // Only finished files are playable; running recordings show up as timers
    if (a["status"].Str() != "fertig")
      continue;
    kodi::addon::PVRRecording rec;
    rec.SetRecordingId(RECORDING_ID_PREFIX + a["id"].Str());
    rec.SetTitle(a["titel"].Str());
    rec.SetEpisodeName(a["untertitel"].Str());
    rec.SetPlot(a["beschreibung"].Str());
    rec.SetChannelName(a["sender_name"].Str());
    rec.SetIconPath(a["bild"].Str());
    rec.SetThumbnailPath(a["bild"].Str());
    rec.SetFanartPath(a["bild"].Str());
    rec.SetRecordingTime(static_cast<time_t>(a["start"].Int()));
    rec.SetDuration(static_cast<int>(a["dauer"].Num()));
    rec.SetPlayCount(static_cast<int>(a["gesehen"].Int()));
    rec.SetLastPlayedPosition(static_cast<int>(a["position"].Num()));
    rec.SetSizeInBytes(a["groesse"].Int());
    rec.SetChannelType(PVR_RECORDING_CHANNEL_TYPE_TV);
    RecorderChannel ch;
    if (channelByUrl(a["sender_url"].Str(), ch))
      rec.SetChannelUid(ch.uniqueId);
    else
      rec.SetChannelUid(PVR_CHANNEL_INVALID_UID);
    recordings.emplace_back(rec);
  }
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR Recorder::GetRecordingStreamProperties(const kodi::addon::PVRRecording& recording,
                                                 std::vector<kodi::addon::PVRStreamProperty>& properties)
{
  const std::string url = GetBaseUrl() + "/datei/" + RecordingServerId(recording.GetRecordingId());
  properties.emplace_back(PVR_STREAM_PROPERTY_STREAMURL, url);
  properties.emplace_back(PVR_STREAM_PROPERTY_MIMETYPE, "video/mp4");
  properties.emplace_back(PVR_STREAM_PROPERTY_ISREALTIMESTREAM, "false");
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR Recorder::DeleteRecording(const kodi::addon::PVRRecording& recording)
{
  JsonValue r;
  std::string error;
  if (!Request("DELETE", "/api/aufnahmen/" + RecordingServerId(recording.GetRecordingId()), "", r, error))
    return Fail("Aufnahme löschen", error);
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR Recorder::SetRecordingPlayCount(const kodi::addon::PVRRecording& recording, int count)
{
  JsonValue r;
  std::string error;
  if (!Request("PUT", "/api/aufnahmen/" + RecordingServerId(recording.GetRecordingId()),
               "{" + JsonField("gesehen", count) + "}", r, error))
    return PVR_ERROR_SERVER_ERROR;
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR Recorder::SetRecordingLastPlayedPosition(const kodi::addon::PVRRecording& recording, int position)
{
  JsonValue r;
  std::string error;
  if (!Request("PUT", "/api/aufnahmen/" + RecordingServerId(recording.GetRecordingId()),
               "{" + JsonField("position", position < 0 ? 0 : position) + "}", r, error))
    return PVR_ERROR_SERVER_ERROR;
  return PVR_ERROR_NO_ERROR;
}

PVR_ERROR Recorder::GetRecordingLastPlayedPosition(const kodi::addon::PVRRecording& recording, int& position)
{
  JsonValue r;
  std::string error;
  if (!Request("GET", "/api/aufnahmen/" + RecordingServerId(recording.GetRecordingId()), "", r, error))
    return PVR_ERROR_SERVER_ERROR;
  position = static_cast<int>(r["position"].Num());
  return PVR_ERROR_NO_ERROR;
}
