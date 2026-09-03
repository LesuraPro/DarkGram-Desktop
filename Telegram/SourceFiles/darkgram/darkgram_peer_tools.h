// This is the source code of DarkGram for Desktop.
#pragma once

#include "base/basic_types.h"

#include <QString>

class PeerData;

namespace DarkGram::PeerTools {

// Records a rename, if the presented name or username actually changed.
//
// Telegram applies such a change silently and keeps no history, which is what makes it
// useful to an attacker: a sold or stolen account keeps its id, its history and its place
// in the chat list while becoming someone else.
//
// Called from the one place holding both the old and the new profile, which runs for every
// peer the server sends. So the comparison happens on values already in memory and nothing
// is written unless something really changed.
void RecordNameChange(
	not_null<PeerData*> peer,
	const QString &newName,
	const QString &newUsername);

// What is known about who this is: an estimated account age, the signals that separate a
// person from a throwaway, and any recorded renames.
void ShowInfo(not_null<PeerData*> peer);

// A locally chosen name for a peer, or an empty string. Kept on this device only: nothing
// here is sent anywhere, which is the point of renaming someone privately.
[[nodiscard]] const QString &Alias(PeerId id);
void SetAlias(PeerId id, const QString &alias);

// A private note about a peer, shown in the info box.
[[nodiscard]] QString Note(PeerId id);
void SetNote(PeerId id, const QString &note);

} // namespace DarkGram::PeerTools
