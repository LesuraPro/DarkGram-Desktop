// This is the source code of DarkGram for Desktop.
#include "darkgram/darkgram_peer_tools.h"

#include "ayu/ayu_settings.h"
#include "boxes/abstract_box.h"
#include "data/data_channel.h"
#include "data/data_chat.h"
#include "data/data_peer.h"
#include "data/data_user.h"
#include "ui/boxes/confirm_box.h"

#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

namespace DarkGram::PeerTools {
namespace {

constexpr auto kLogLimit = 100;

struct Presented {
	QString name;
	QString username;
};

[[nodiscard]] Presented PresentedOf(not_null<PeerData*> peer) {
	if (const auto user = peer->asUser()) {
		return { user->name(), user->username() };
	} else if (const auto channel = peer->asChannel()) {
		return { channel->name(), channel->username() };
	}
	return { peer->name(), QString() };
}

[[nodiscard]] QJsonArray LoadLog() {
	const auto stored = AyuSettings::getInstance().nameChangeLog();
	if (stored.isEmpty()) {
		return QJsonArray();
	}
	return QJsonDocument::fromJson(stored.toUtf8()).array();
}

void SaveLog(const QJsonArray &log) {
	AyuSettings::getInstance().setNameChangeLog(
		QString::fromUtf8(QJsonDocument(log).toJson(QJsonDocument::Compact)));
}

// Telegram issues user ids in ascending order, so an id places an account on a timeline.
// Anchors are (id, year, month); anything between two of them is interpolated.
//
// This is an estimate and is labelled as one. Allocation has not been perfectly monotonic
// -- imported accounts and the 2022 move to 64-bit ids both disturb it -- so the answer is
// a period, never a date, and is withheld above the last anchor, where the only honest
// thing to say is "recent".
[[nodiscard]] QString AccountPeriod(uint64 id) {
	struct Anchor {
		uint64 id;
		int year;
		int month;
	};
	static const Anchor anchors[] = {
		{ 44634663, 2015, 1 },
		{ 101260938, 2016, 1 },
		{ 164788718, 2017, 1 },
		{ 285253072, 2018, 1 },
		{ 543093692, 2019, 1 },
		{ 925078845, 2020, 1 },
		{ 1524312228, 2021, 1 },
		{ 2166527034, 2022, 1 },
	};
	const auto count = int(std::size(anchors));
	if (!id) {
		return QString();
	} else if (id < anchors[0].id) {
		return u"< "_q + QString::number(anchors[0].year);
	} else if (id > anchors[count - 1].id) {
		return QString();
	}
	for (auto i = 1; i != count; ++i) {
		const auto &upper = anchors[i];
		if (id > upper.id) {
			continue;
		}
		const auto &lower = anchors[i - 1];
		const auto span = double(upper.id - lower.id);
		if (span <= 0.) {
			return QString::number(lower.year);
		}
		const auto progress = double(id - lower.id) / span;
		const auto lowerMonths = lower.year * 12 + (lower.month - 1);
		const auto upperMonths = upper.year * 12 + (upper.month - 1);
		const auto months = lowerMonths
			+ int(std::round((upperMonths - lowerMonths) * progress));
		return QString::asprintf("%04d-%02d", months / 12, months % 12 + 1);
	}
	return QString();
}

} // namespace

void RecordNameChange(
		not_null<PeerData*> peer,
		const QString &newName,
		const QString &newUsername) {
	const auto before = PresentedOf(peer);
	// Cheap comparison of values already in memory; nothing below runs without a change.
	if (before.name == newName && before.username == newUsername) {
		return;
	} else if (before.name.isEmpty() && before.username.isEmpty()) {
		// The peer had no name yet: this is the first load, not a rename.
		return;
	} else if (newName.isEmpty() && newUsername.isEmpty()) {
		return;
	} else if (!AyuSettings::getInstance().trackNameChanges()) {
		return;
	}
	auto log = LoadLog();
	auto entry = QJsonObject();
	entry.insert(u"p"_q, QString::number(peer->id.value));
	entry.insert(u"t"_q, qint64(QDateTime::currentSecsSinceEpoch()));
	entry.insert(u"n"_q, before.name);
	entry.insert(u"N"_q, newName);
	entry.insert(u"u"_q, before.username);
	entry.insert(u"U"_q, newUsername);
	log.append(entry);
	while (log.size() > kLogLimit) {
		log.removeFirst();
	}
	SaveLog(log);
}

void ShowInfo(not_null<PeerData*> peer) {
	auto lines = QStringList();

	if (const auto user = peer->asUser()) {
		const auto period = AccountPeriod(peerToUser(user->id).bare);
		lines.append(u"Возраст аккаунта: "_q
			+ (period.isEmpty()
				? u"недавний (оценка недоступна)"_q
				: u"~"_q + period));

		auto marks = QStringList();
		if (user->username().isEmpty()) {
			marks.append(u"нет юзернейма"_q);
		}
		if (!user->hasUserpic()) {
			marks.append(u"нет фото"_q);
		}
		if (user->isScam()) {
			marks.append(u"помечен как мошенник"_q);
		}
		if (user->isFake()) {
			marks.append(u"помечен как подделка"_q);
		}
		if (!marks.isEmpty()) {
			lines.append(u"Признаки: "_q + marks.join(u", "_q));
		}
		if (user->isContact()) {
			lines.append(u"В контактах"_q);
		}
	}

	const auto id = QString::number(peer->id.value);
	const auto log = LoadLog();
	auto renames = QStringList();
	for (const auto &value : log) {
		const auto entry = value.toObject();
		if (entry.value(u"p"_q).toString() != id) {
			continue;
		}
		const auto when = QDateTime::fromSecsSinceEpoch(
			entry.value(u"t"_q).toInteger()).toString(u"dd.MM.yyyy"_q);
		const auto oldName = entry.value(u"n"_q).toString();
		const auto newName = entry.value(u"N"_q).toString();
		if (oldName != newName) {
			renames.append(u"Переименован "_q + when + u": "_q
				+ oldName + u" -> "_q + newName);
		}
		const auto oldUser = entry.value(u"u"_q).toString();
		const auto newUser = entry.value(u"U"_q).toString();
		if (oldUser != newUser) {
			renames.append(u"Смена юзернейма "_q + when + u": "_q
				+ (oldUser.isEmpty() ? u"-"_q : u"@"_q + oldUser)
				+ u" -> "_q
				+ (newUser.isEmpty() ? u"-"_q : u"@"_q + newUser));
		}
	}
	// Only the last few: the point is whether this identity moved, not a full ledger.
	while (renames.size() > 6) {
		renames.removeFirst();
	}
	lines.append(renames);

	if (lines.isEmpty()) {
		lines.append(u"Ничего примечательного."_q);
	}
	Ui::show(Ui::MakeInformBox({
		.text = lines.join(u"\n"_q),
		.title = u"DarkGram: о собеседнике"_q,
	}));
}

} // namespace DarkGram::PeerTools
