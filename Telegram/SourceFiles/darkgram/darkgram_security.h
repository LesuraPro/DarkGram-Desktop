// This is the source code of DarkGram for Desktop.
#pragma once

#include "base/basic_types.h"

#include <QString>
#include <QStringList>

class DocumentData;

namespace DarkGram::Security {

// What a link really points at.
//
// Each case is a way of making the part of an address a person glances at differ from the
// part a browser acts on: a decoy before an @, which the browser discards; a punycode or
// mixed-alphabet domain that renders like a familiar one; a bare IP with no name at all.
// Domains on the user's own blocklist are refused outright.
struct LinkCheck {
	QString host;
	QStringList reasons;
	bool blocked = false;
};
[[nodiscard]] LinkCheck InspectLink(const QString &url);

// An unverified name that claims authority: "Telegram Support", "Служба безопасности".
// Latin terms are also matched after folding Cyrillic look-alikes into Latin.
[[nodiscard]] bool ImitatesService(const QString &name, const QString &username);

// Whether a JPEG or TIFF file records the coordinates it was taken at. Reads only the
// header, so it is cheap enough to run on the files being sent.
[[nodiscard]] bool HasGpsLocation(const QString &path);

// SHA-256 of a downloaded file, computed off the main thread and shown with a copy button.
void ShowFileHash(not_null<DocumentData*> document);

// A local record of everything the protections caught. Nothing here is sent anywhere.
void LogEvent(const QString &kind, const QString &detail);
void ShowSecurityLog();

} // namespace DarkGram::Security
