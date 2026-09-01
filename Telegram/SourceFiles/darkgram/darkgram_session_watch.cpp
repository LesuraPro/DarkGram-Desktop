// This is the source code of DarkGram for Desktop.
#include "darkgram/darkgram_session_watch.h"

#include "api/api_authorizations.h"
#include "apiwrap.h"
#include "ayu/ayu_settings.h"
#include "boxes/abstract_box.h"
#include "main/main_session.h"
#include "ui/boxes/confirm_box.h"

#include <QSet>

namespace DarkGram::SessionWatch {
namespace {

bool CheckedThisRun/* = false*/;
rpl::lifetime Lifetime;

[[nodiscard]] QSet<uint64> KnownHashes() {
	auto result = QSet<uint64>();
	const auto stored = AyuSettings::getInstance().knownSessionHashes();
	if (stored.isEmpty()) {
		return result;
	}
	for (const auto &part : stored.split(',', Qt::SkipEmptyParts)) {
		auto ok = false;
		const auto value = part.toULongLong(&ok);
		if (ok) {
			result.insert(value);
		}
	}
	return result;
}

void Report(const Api::Authorizations::List &list) {
	const auto known = KnownHashes();

	// Record before presenting: a failure to show must not leave the same session
	// warning on every launch.
	auto stored = QStringList();
	for (const auto &entry : list) {
		stored.append(QString::number(entry.hash));
	}
	AyuSettings::getInstance().setKnownSessionHashes(stored.join(','));

	if (known.isEmpty()) {
		// The first run only records. Alerting about sessions that already existed says
		// nothing about a compromise and teaches the warning to be ignored.
		return;
	}

	auto lines = QStringList();
	for (const auto &entry : list) {
		if (!entry.hash || known.contains(entry.hash)) {
			continue;
		}
		auto line = entry.name;
		if (!entry.info.isEmpty()) {
			line += u" - "_q + entry.info;
		}
		auto origin = entry.location;
		if (!entry.ip.isEmpty()) {
			origin = origin.isEmpty() ? entry.ip : origin + u", "_q + entry.ip;
		}
		if (!origin.isEmpty()) {
			line += u"\n"_q + origin;
		}
		lines.append(line);
	}
	if (lines.isEmpty()) {
		return;
	}
	Ui::show(Ui::MakeInformBox({
		.text = u"В аккаунт вошёл сеанс, которого раньше не было:\n\n"_q
			+ lines.join(u"\n\n"_q),
		.title = u"Новый сеанс"_q,
	}));
}

} // namespace

void Check(not_null<Main::Session*> session) {
	if (CheckedThisRun || !AyuSettings::getInstance().sessionWatchEnabled()) {
		return;
	}
	CheckedThisRun = true;

	auto &authorizations = session->api().authorizations();
	authorizations.listValue(
	) | rpl::filter([](const Api::Authorizations::List &list) {
		// The list is published empty before the request lands.
		return !list.empty();
	}) | rpl::take(1) | rpl::start_with_next([](
			const Api::Authorizations::List &list) {
		Report(list);
	}, Lifetime);

	authorizations.reload();
}

} // namespace DarkGram::SessionWatch
