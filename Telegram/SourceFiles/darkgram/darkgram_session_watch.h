// This is the source code of DarkGram for Desktop.
#pragma once

#include "base/basic_types.h"

namespace Main {
class Session;
} // namespace Main

namespace DarkGram::SessionWatch {

// Tells you when a session appears that was not there before.
//
// Telegram already lists active sessions, but the list only speaks when opened. An account
// is taken over quietly, and by the time anyone thinks to check that screen the interesting
// part has already happened.
//
// Safe to call repeatedly: it acts once per run.
void Check(not_null<Main::Session*> session);

} // namespace DarkGram::SessionWatch
