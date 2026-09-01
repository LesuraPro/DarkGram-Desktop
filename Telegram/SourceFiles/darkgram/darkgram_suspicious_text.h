// This is the source code of DarkGram for Desktop.
#pragma once

#include <QString>

// Detection for names that do not read the way they render.
//
// Two separate tricks are covered:
//
//   1. Bidirectional overrides. U+202E and friends tell the renderer to lay out the
//      following text right to left. The character is invisible and survives copy and
//      paste, so a name ending "fdp.exe" is drawn as "exe.pdf" -- the reader sees a
//      document, the system sees an executable.
//
//   2. Homoglyphs. Cyrillic "с" and Latin "c" render identically, so "Ассount" and
//      "Account" cannot be told apart by eye. Fake support channels are built from this.
//
// Nothing here blocks anything. Both tricks only work while the rendered name and the
// real one disagree, so the defence is to make them agree.

namespace DarkGram {

struct NameInspection {
	bool reordersText = false;
	bool hidesCharacters = false;
	bool mixesScripts = false;

	[[nodiscard]] bool isSuspicious() const {
		return reordersText || hidesCharacters || mixesScripts;
	}
};

// Reports what is wrong with a name, without changing it.
[[nodiscard]] NameInspection InspectName(const QString &name);

// The name with every reordering and invisible character removed, so that what is drawn
// is what the system will actually act on.
[[nodiscard]] QString SanitizedName(const QString &name);

// Removes query parameters that identify the person following a link rather than
// selecting what is shown. They survive copying and forwarding, so a link shared in a
// chat otherwise carries the identity of whoever received it first to everyone after.
//
// Non-http(s) links, links without a query, and links carrying no tracking parameter are
// returned untouched: a guess here silently breaks links, which is worse than tracking.
[[nodiscard]] QString StripTrackingParameters(const QString &url);

// Why a file is worth a second look before opening, or an empty string when it is an
// ordinary document. Judged on the sanitised name, so a reordering character cannot hide
// the extension being checked.
[[nodiscard]] QString DangerousFileReason(const QString &fileName);

} // namespace DarkGram
