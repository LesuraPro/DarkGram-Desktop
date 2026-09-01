// This is the source code of DarkGram for Desktop.
#include "darkgram/darkgram_suspicious_text.h"

#include <QSet>
#include <QUrl>
#include <QUrlQuery>

namespace DarkGram {
namespace {

// Invisible characters that reorder the text around them.
[[nodiscard]] bool IsReordering(char32_t code) {
	switch (code) {
	case 0x202A: // LEFT-TO-RIGHT EMBEDDING
	case 0x202B: // RIGHT-TO-LEFT EMBEDDING
	case 0x202C: // POP DIRECTIONAL FORMATTING
	case 0x202D: // LEFT-TO-RIGHT OVERRIDE
	case 0x202E: // RIGHT-TO-LEFT OVERRIDE
	case 0x2066: // LEFT-TO-RIGHT ISOLATE
	case 0x2067: // RIGHT-TO-LEFT ISOLATE
	case 0x2068: // FIRST STRONG ISOLATE
	case 0x2069: // POP DIRECTIONAL ISOLATE
		return true;
	default:
		return false;
	}
}

// Characters that occupy no space, used to break a string up so it evades matching
// while still reading normally.
[[nodiscard]] bool IsInvisible(char32_t code) {
	switch (code) {
	case 0x200B: // ZERO WIDTH SPACE
	case 0x200C: // ZERO WIDTH NON-JOINER
	case 0x200D: // ZERO WIDTH JOINER
	case 0x2060: // WORD JOINER
	case 0xFEFF: // ZERO WIDTH NO-BREAK SPACE
		return true;
	default:
		return false;
	}
}

enum class Script {
	None,
	Latin,
	Cyrillic,
	Greek,
};

[[nodiscard]] Script ScriptOf(char32_t code) {
	if ((code >= 0x0041 && code <= 0x005A) || (code >= 0x0061 && code <= 0x007A)) {
		return Script::Latin;
	} else if (code >= 0x0400 && code <= 0x052F) {
		return Script::Cyrillic;
	} else if (code >= 0x0370 && code <= 0x03FF) {
		return Script::Greek;
	}
	// Everything else -- digits, punctuation, emoji, CJK, Arabic -- carries no homoglyph
	// risk against Latin, so it neither counts as a script nor splits a word.
	return Script::None;
}

} // namespace

NameInspection InspectName(const QString &name) {
	auto result = NameInspection();

	auto scriptsInWord = QSet<int>();
	auto sawLetter = false;

	const auto closeWord = [&] {
		if (scriptsInWord.size() > 1) {
			result.mixesScripts = true;
		}
		scriptsInWord.clear();
		sawLetter = false;
	};

	for (const auto ch : name.toUcs4()) {
		if (IsReordering(ch)) {
			result.reordersText = true;
			continue;
		} else if (IsInvisible(ch)) {
			result.hidesCharacters = true;
			continue;
		}
		const auto script = ScriptOf(ch);
		if (script != Script::None) {
			sawLetter = true;
			scriptsInWord.insert(static_cast<int>(script));
		} else if (QChar::isSpace(ch)) {
			// Only whitespace ends a word. Mixing alphabets across a dot or a hyphen is
			// just as deliberate as mixing them mid-word, and splitting there would hide
			// exactly the file names this is meant to catch.
			closeWord();
		}
	}
	if (sawLetter) {
		closeWord();
	}
	return result;
}

QString SanitizedName(const QString &name) {
	auto result = QString();
	result.reserve(name.size());
	for (const auto ch : name.toUcs4()) {
		if (IsReordering(ch) || IsInvisible(ch)) {
			continue;
		}
		result.append(QString::fromUcs4(&ch, 1));
	}
	return result;
}


namespace {

[[nodiscard]] bool IsTrackingParameter(const QString &name) {
	static const auto known = QSet<QString>{
		u"fbclid"_q, u"gclid"_q, u"dclid"_q, u"gbraid"_q, u"wbraid"_q, u"msclkid"_q,
		u"yclid"_q, u"twclid"_q, u"ttclid"_q, u"igshid"_q, u"mc_eid"_q, u"mc_cid"_q,
		u"_openstat"_q, u"vero_id"_q, u"wickedid"_q, u"oly_enc_id"_q, u"oly_anon_id"_q,
		u"ref_src"_q, u"ref_url"_q,
	};
	const auto lowered = name.toLower();
	// Every utm_* is analytics by construction, so match the prefix rather than list them.
	return lowered.startsWith(u"utm_"_q) || known.contains(lowered);
}

} // namespace

QString StripTrackingParameters(const QString &url) {
	auto parsed = QUrl(url);
	const auto scheme = parsed.scheme().toLower();
	if (scheme != u"http"_q && scheme != u"https"_q) {
		return url;
	}
	auto query = QUrlQuery(parsed);
	const auto items = query.queryItems();
	if (items.isEmpty()) {
		return url;
	}
	auto kept = QList<QPair<QString, QString>>();
	for (const auto &item : items) {
		if (!IsTrackingParameter(item.first)) {
			kept.append(item);
		}
	}
	if (kept.size() == items.size()) {
		return url;
	}
	auto updated = QUrlQuery();
	updated.setQueryItems(kept);
	parsed.setQuery(updated);
	return parsed.toString();
}

} // namespace DarkGram
