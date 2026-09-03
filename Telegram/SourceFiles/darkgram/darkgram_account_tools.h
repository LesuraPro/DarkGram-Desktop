// This is the source code of DarkGram for Desktop.
#pragma once

#include "base/basic_types.h"

namespace Main {
class Session;
} // namespace Main

namespace DarkGram::AccountTools {

// What a stranger can see about you.
//
// Telegram has the settings, spread over a dozen screens, each showing its own value and
// none showing the total. Nobody audits twelve screens, so in practice the answer is "I
// assume it's fine". This is that answer in one list.
void ShowPrivacyAudit(not_null<Main::Session*> session);

// What the connection is actually doing, rather than what is configured. The proxy screen
// shows the setting; a proxy that failed and fell back leaves it switched on while the
// traffic goes direct.
void ShowConnectionInfo(not_null<Main::Session*> session);

// Turns ghost mode on and off by the clock, using the fork's own toggle rather than
// touching how ghost mode works. Only acts when the window boundary is crossed, so a
// manual toggle inside the window is not overwritten on the next tick.
void ApplyGhostSchedule(not_null<Main::Session*> session);

// Copies every setting out to a file of the reader's choosing, and back. The fork already
// keeps its settings as one JSON file, so this moves that file rather than serialising
// the same values a second time and letting the two drift.
void ExportSettings();
void ImportSettings();

} // namespace DarkGram::AccountTools
