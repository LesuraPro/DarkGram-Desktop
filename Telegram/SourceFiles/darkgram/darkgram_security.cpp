// This is the source code of DarkGram for Desktop.
#include "darkgram/darkgram_security.h"

#include "ayu/ayu_settings.h"
#include "boxes/abstract_box.h"
#include "data/data_document.h"
#include "ui/boxes/confirm_box.h"

#include <QClipboard>
#include <QCryptographicHash>
#include <QDateTime>
#include <QFile>
#include <QGuiApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>

#include <optional>

namespace DarkGram::Security {
namespace {

constexpr auto kLogLimit = 200;
constexpr auto kLogShown = 40;
// Enough for any camera's header; the image data after it is never needed.
constexpr auto kExifReadLimit = 1024 * 1024;
constexpr auto kMaxIfdEntries = uint32(512);

enum class Script {
	None,
	Latin,
	Cyrillic,
	Greek,
};

[[nodiscard]] Script ScriptOf(uint code) {
	if ((code >= 0x41 && code <= 0x5A) || (code >= 0x61 && code <= 0x7A)) {
		return Script::Latin;
	} else if (code >= 0x400 && code <= 0x52F) {
		return Script::Cyrillic;
	} else if (code >= 0x370 && code <= 0x3FF) {
		return Script::Greek;
	}
	return Script::None;
}

[[nodiscard]] bool IsAsciiDigits(const QString &text) {
	if (text.isEmpty()) {
		return false;
	}
	for (const auto ch : text) {
		if (ch.unicode() < '0' || ch.unicode() > '9') {
			return false;
		}
	}
	return true;
}

[[nodiscard]] QStringList BlockedDomains() {
	auto result = QStringList();
	const auto parts = AyuSettings::getInstance().blockedDomains().split(
		QRegularExpression(u"[,;\\s]+"_q),
		Qt::SkipEmptyParts);
	for (const auto &part : parts) {
		auto domain = part.toLower();
		const auto scheme = domain.indexOf(u"://"_q);
		if (scheme >= 0) {
			domain = domain.mid(scheme + 3);
		}
		if (domain.startsWith(u"*."_q)) {
			domain = domain.mid(2);
		}
		while (domain.endsWith(u"/"_q) || domain.endsWith(u"."_q)) {
			domain.chop(1);
		}
		if (!domain.isEmpty()) {
			result.append(domain);
		}
	}
	return result;
}

// The host of an http(s) or scheme-less link, taken apart by hand: QUrl normalises
// user-info and non-ASCII hosts in ways that would hide exactly what is being checked.
struct Authority {
	QString host;
	bool hadUserInfo = false;
};

[[nodiscard]] std::optional<Authority> ParseAuthority(const QString &url) {
	auto rest = url.trimmed();
	const auto schemeEnd = rest.indexOf(u"://"_q);
	if (schemeEnd >= 0) {
		const auto scheme = rest.left(schemeEnd).toLower();
		if (scheme != u"http"_q && scheme != u"https"_q) {
			return std::nullopt;
		}
		rest = rest.mid(schemeEnd + 3);
	} else if (rest.contains(u":"_q) && !rest.contains(u"."_q)) {
		// mailto:, tel: and similar carry no host to judge.
		return std::nullopt;
	}
	const auto end = rest.indexOf(QRegularExpression(u"[/?#]"_q));
	if (end >= 0) {
		rest = rest.left(end);
	}
	auto result = Authority();
	const auto at = rest.lastIndexOf(u"@"_q);
	if (at >= 0) {
		result.hadUserInfo = true;
		rest = rest.mid(at + 1);
	}
	if (rest.startsWith(u"["_q)) {
		const auto close = rest.indexOf(u"]"_q);
		if (close >= 0) {
			rest = rest.left(close + 1);
		}
	} else {
		const auto colon = rest.lastIndexOf(u":"_q);
		if (colon >= 0 && IsAsciiDigits(rest.mid(colon + 1))) {
			rest = rest.left(colon);
		}
	}
	result.host = rest.toLower();
	if (result.host.isEmpty()) {
		return std::nullopt;
	}
	return result;
}

[[nodiscard]] QChar FoldToLatin(QChar ch) {
	switch (ch.unicode()) {
	case 0x430: return QChar(u'a');
	case 0x432: return QChar(u'b');
	case 0x435: return QChar(u'e');
	case 0x43A: return QChar(u'k');
	case 0x43C: return QChar(u'm');
	case 0x43D: return QChar(u'h');
	case 0x43E: return QChar(u'o');
	case 0x440: return QChar(u'p');
	case 0x441: return QChar(u'c');
	case 0x442: return QChar(u't');
	case 0x443: return QChar(u'y');
	case 0x445: return QChar(u'x');
	case 0x455: return QChar(u's');
	case 0x456: return QChar(u'i');
	}
	return ch;
}

[[nodiscard]] QString KindTitle(const QString &kind) {
	if (kind == u"session"_q) {
		return u"Новый сеанс"_q;
	} else if (kind == u"rename"_q) {
		return u"Смена имени"_q;
	} else if (kind == u"blockedLink"_q) {
		return u"Заблокирована ссылка"_q;
	} else if (kind == u"suspiciousLink"_q) {
		return u"Подозрительная ссылка"_q;
	} else if (kind == u"fileLocation"_q) {
		return u"Файл с геометкой"_q;
	}
	return kind;
}

[[nodiscard]] QJsonArray LoadLog() {
	const auto stored = AyuSettings::getInstance().securityLog();
	if (stored.isEmpty()) {
		return QJsonArray();
	}
	return QJsonDocument::fromJson(stored.toUtf8()).array();
}

// Offsets inside a TIFF block are relative to its header and may be in either byte order.
class TiffReader {
public:
	TiffReader(const QByteArray &data, int base, bool little)
	: _data(data)
	, _base(base)
	, _little(little) {
	}

	[[nodiscard]] std::optional<uint32> read(int offset, int size) const {
		const auto at = qint64(_base) + offset;
		if (offset < 0 || at < 0 || at + size > _data.size()) {
			return std::nullopt;
		}
		auto result = uint32(0);
		for (auto i = 0; i != size; ++i) {
			const auto byte = uint32(uchar(_data[int(at) + i]));
			result |= _little
				? (byte << (8 * i))
				: (byte << (8 * (size - 1 - i)));
		}
		return result;
	}

private:
	const QByteArray &_data;
	int _base = 0;
	bool _little = false;

};

[[nodiscard]] bool TiffHasGps(const QByteArray &data, int base) {
	if (base < 0 || base + 8 > data.size()) {
		return false;
	}
	const auto first = data[base];
	const auto second = data[base + 1];
	const auto little = (first == 'I' && second == 'I');
	if (!little && !(first == 'M' && second == 'M')) {
		return false;
	}
	const auto reader = TiffReader(data, base, little);
	const auto ifd0 = reader.read(4, 4);
	if (!ifd0 || *ifd0 > uint32(data.size())) {
		return false;
	}
	const auto count = reader.read(int(*ifd0), 2);
	if (!count || *count > kMaxIfdEntries) {
		return false;
	}
	for (auto i = 0; i != int(*count); ++i) {
		const auto entry = int(*ifd0) + 2 + i * 12;
		const auto tag = reader.read(entry, 2);
		if (!tag) {
			return false;
		} else if (*tag != 0x8825) {
			continue;
		}
		// The GPS directory. Present but empty happens; only a coordinate counts.
		const auto gps = reader.read(entry + 8, 4);
		if (!gps || *gps > uint32(data.size())) {
			return false;
		}
		const auto gpsCount = reader.read(int(*gps), 2);
		if (!gpsCount || *gpsCount > kMaxIfdEntries) {
			return false;
		}
		for (auto j = 0; j != int(*gpsCount); ++j) {
			const auto gpsTag = reader.read(int(*gps) + 2 + j * 12, 2);
			if (!gpsTag) {
				return false;
			} else if (*gpsTag == 0x0002 || *gpsTag == 0x0004) {
				return true;
			}
		}
		return false;
	}
	return false;
}

} // namespace

LinkCheck InspectLink(const QString &url) {
	auto result = LinkCheck();
	const auto authority = ParseAuthority(url);
	if (!authority) {
		return result;
	}
	const auto &host = authority->host;
	result.host = host;

	// The blocklist is the user's own decision, so it applies whether or not the address
	// checks are switched on.
	for (const auto &domain : BlockedDomains()) {
		if (host == domain || host.endsWith(u"."_q + domain)) {
			result.blocked = true;
			result.reasons.append(u"Домен в вашем чёрном списке."_q);
			return result;
		}
	}
	if (!AyuSettings::getInstance().checkLinkAddress()) {
		return result;
	}

	if (authority->hadUserInfo) {
		result.reasons.append(u"Перед знаком @ стоит обманка: браузер её отбросит и откроет адрес после @."_q);
	}
	static const auto ipv4 = QRegularExpression(
		u"^[0-9]{1,3}(\\.[0-9]{1,3}){3}$"_q);
	if (host.startsWith(u"["_q) || ipv4.match(host).hasMatch()) {
		result.reasons.append(u"Вместо имени сайта голый IP-адрес. Обычным сайтам это не нужно."_q);
		return result;
	}
	const auto labels = host.split(u"."_q, Qt::SkipEmptyParts);
	auto punycode = false;
	auto mixed = false;
	for (const auto &label : labels) {
		if (label.startsWith(u"xn--"_q)) {
			punycode = true;
		}
		auto seen = std::optional<Script>();
		for (const auto code : label.toUcs4()) {
			const auto script = ScriptOf(code);
			if (script == Script::None) {
				continue;
			} else if (seen && *seen != script) {
				mixed = true;
			}
			seen = script;
		}
	}
	if (punycode) {
		result.reasons.append(u"Домен записан в punycode (xn--). Так выглядит поддельный адрес, скопированный как текст."_q);
	}
	if (mixed) {
		result.reasons.append(u"В домене смешаны алфавиты: часть букв выглядит как латиница, но ей не является."_q);
	}
	return result;
}

bool ImitatesService(const QString &name, const QString &username) {
	// Kept to words that claim authority. "admin" or "premium" alone would flag every
	// badminton club and every shop, and a warning that is usually wrong stops being read.
	static const auto latin = QStringList{
		u"telegram"_q, u"support"_q, u"security"_q, u"official"_q,
		u"administrator"_q, u"moderator"_q, u"notification"_q,
		u"verify"_q, u"verification"_q,
	};
	static const auto cyrillic = QStringList{
		u"телеграм"_q, u"поддержк"_q, u"безопасност"_q, u"официальн"_q,
		u"администрац"_q, u"модератор"_q, u"служба"_q, u"уведомлен"_q,
		u"верификац"_q,
	};
	const auto text = (name + u" "_q + username).toLower();
	for (const auto &term : cyrillic) {
		if (text.contains(term)) {
			return true;
		}
	}
	auto folded = QString();
	folded.reserve(text.size());
	for (const auto ch : text) {
		folded.append(FoldToLatin(ch));
	}
	for (const auto &term : latin) {
		if (folded.contains(term)) {
			return true;
		}
	}
	return false;
}

bool HasGpsLocation(const QString &path) {
	auto file = QFile(path);
	if (!file.open(QIODevice::ReadOnly)) {
		return false;
	}
	const auto data = file.read(kExifReadLimit);
	if (data.size() < 8) {
		return false;
	}
	// A TIFF (and DNG) file is a TIFF block from its first byte.
	if ((data[0] == 'I' && data[1] == 'I') || (data[0] == 'M' && data[1] == 'M')) {
		return TiffHasGps(data, 0);
	}
	if (uchar(data[0]) != 0xFF || uchar(data[1]) != 0xD8) {
		return false;
	}
	// JPEG: walk the segments before the image data, looking for the Exif one.
	static const auto exifMark = QByteArray("Exif\0\0", 6);
	auto at = 2;
	while (at + 4 <= data.size()) {
		if (uchar(data[at]) != 0xFF) {
			return false;
		}
		const auto marker = uchar(data[at + 1]);
		if (marker == 0xFF) {
			// Fill byte between segments.
			++at;
			continue;
		} else if (marker == 0xD9 || marker == 0xDA) {
			return false;
		}
		const auto length = int((uint32(uchar(data[at + 2])) << 8)
			| uint32(uchar(data[at + 3])));
		if (length < 2) {
			return false;
		}
		if (marker == 0xE1
			&& at + 10 <= data.size()
			&& data.mid(at + 4, 6) == exifMark
			&& TiffHasGps(data, at + 10)) {
			return true;
		}
		at += 2 + length;
	}
	return false;
}

void ShowFileHash(not_null<DocumentData*> document) {
	// Only a file already on this device is hashed. Downloading something in order to
	// decide whether it is safe would defeat the point.
	const auto path = document->filepath(true);
	if (path.isEmpty()) {
		Ui::show(Ui::MakeInformBox({
			.text = u"Файл ещё не загружен. Хэш считается только по скачанному файлу."_q,
			.title = u"SHA-256"_q,
		}));
		return;
	}
	const auto name = document->filename();
	crl::async([=] {
		auto result = QString();
		auto file = QFile(path);
		if (file.open(QIODevice::ReadOnly)) {
			auto hash = QCryptographicHash(QCryptographicHash::Sha256);
			if (hash.addData(&file)) {
				result = QString::fromLatin1(hash.result().toHex());
			}
		}
		crl::on_main([=] {
			if (result.isEmpty()) {
				Ui::show(Ui::MakeInformBox({
					.text = u"Не удалось прочитать файл."_q,
					.title = u"SHA-256"_q,
				}));
				return;
			}
			Ui::show(Ui::MakeConfirmBox({
				.text = (name.isEmpty() ? result : (name + u"\n\n"_q + result)),
				.confirmed = [=](Fn<void()> close) {
					QGuiApplication::clipboard()->setText(result);
					close();
				},
				.confirmText = u"Скопировать"_q,
				.cancelText = u"Закрыть"_q,
				.title = u"SHA-256"_q,
			}));
		});
	});
}

void LogEvent(const QString &kind, const QString &detail) {
	auto log = LoadLog();
	auto entry = QJsonObject();
	entry.insert(u"t"_q, qint64(QDateTime::currentSecsSinceEpoch()));
	entry.insert(u"k"_q, kind);
	entry.insert(u"d"_q, detail);
	log.append(entry);
	while (log.size() > kLogLimit) {
		log.removeFirst();
	}
	AyuSettings::getInstance().setSecurityLog(
		QString::fromUtf8(QJsonDocument(log).toJson(QJsonDocument::Compact)));
}

void ShowSecurityLog() {
	const auto log = LoadLog();
	auto lines = QStringList();
	// Newest first, which is the order anyone reading it wants.
	for (auto i = int(log.size()) - 1; i >= 0 && lines.size() < kLogShown; --i) {
		const auto entry = log[i].toObject();
		const auto when = QDateTime::fromSecsSinceEpoch(
			entry.value(u"t"_q).toInteger()).toString(u"dd.MM HH:mm"_q);
		auto line = when + u" — "_q + KindTitle(entry.value(u"k"_q).toString());
		const auto detail = entry.value(u"d"_q).toString();
		if (!detail.isEmpty()) {
			line += u": "_q + detail;
		}
		lines.append(line);
	}
	if (lines.isEmpty()) {
		Ui::show(Ui::MakeInformBox({
			.text = u"Пока ничего не произошло."_q,
			.title = u"Журнал безопасности"_q,
		}));
		return;
	}
	Ui::show(Ui::MakeConfirmBox({
		.text = lines.join(u"\n\n"_q),
		.confirmed = [](Fn<void()> close) {
			AyuSettings::getInstance().setSecurityLog(QString());
			close();
		},
		.confirmText = u"Очистить"_q,
		.cancelText = u"Закрыть"_q,
		.title = u"Журнал безопасности"_q,
	}));
}

} // namespace DarkGram::Security
