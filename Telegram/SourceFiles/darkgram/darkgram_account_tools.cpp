// This is the source code of DarkGram for Desktop.
#include "darkgram/darkgram_account_tools.h"

#include "api/api_user_privacy.h"
#include "apiwrap.h"
#include "boxes/abstract_box.h"
#include "core/application.h"
#include "core/core_settings.h"
#include "core/core_settings_proxy.h"
#include "main/main_account.h"
#include "main/main_session.h"
#include "mtproto/mtp_instance.h"
#include "mtproto/mtproto_proxy_data.h"
#include "ui/boxes/confirm_box.h"

namespace DarkGram::AccountTools {
namespace {

rpl::lifetime Lifetime;

using Key = Api::UserPrivacy::Key;
using Option = Api::UserPrivacy::Option;

struct Named {
	Key key;
	QString title;
};

[[nodiscard]] std::vector<Named> AuditedKeys() {
	return {
		{ Key::LastSeen, u"Время в сети"_q },
		{ Key::ProfilePhoto, u"Фото профиля"_q },
		{ Key::Forwards, u"Ссылка при пересылке"_q },
		{ Key::PhoneNumber, u"Номер телефона"_q },
		{ Key::Invites, u"Добавление в группы"_q },
		{ Key::Calls, u"Звонки"_q },
		{ Key::Voices, u"Голосовые сообщения"_q },
		{ Key::About, u"О себе"_q },
	};
}

} // namespace

void ShowPrivacyAudit(not_null<Main::Session*> session) {
	auto &privacy = session->api().userPrivacy();
	const auto named = AuditedKeys();

	// Each key is a separate request with a separate producer, and rpl::combine here is
	// variadic over a fixed list rather than a vector, so the answers are gathered by
	// hand and reported once the last one lands.
	struct Gather {
		std::vector<std::optional<Option>> options;
		int remaining = 0;
		bool reported = false;
	};
	const auto state = std::make_shared<Gather>();
	state->options.resize(named.size());
	state->remaining = int(named.size());

	for (auto i = 0; i != int(named.size()); ++i) {
		const auto index = i;
		privacy.reload(named[index].key);
		privacy.value(
			named[index].key
		) | rpl::take(1) | on_next([=](const Api::UserPrivacy::Rule &rule) {
			if (state->reported || state->options[index].has_value()) {
				return;
			}
			state->options[index] = rule.option;
			if (--state->remaining > 0) {
				return;
			}
			state->reported = true;

			auto exposed = QStringList();
			auto restricted = 0;
			for (auto j = 0; j != int(named.size()); ++j) {
				if (state->options[j] == Option::Everyone) {
					exposed.append(named[j].title);
				} else {
					++restricted;
				}
			}
			auto text = exposed.isEmpty()
				? u"Всем не видно ничего."_q
				: (u"Видно всем:\n- "_q + exposed.join(u"\n- "_q));
			if (restricted > 0) {
				text += u"\n\nОграниченных настроек: "_q
					+ QString::number(restricted);
			}
			Ui::show(Ui::MakeInformBox({
				.text = text,
				.title = u"Что видно посторонним"_q,
			}));
		}, Lifetime);
	}
}

void ShowConnectionInfo(not_null<Main::Session*> session) {
	auto lines = QStringList();

	lines.append(u"Дата-центр: DC"_q
		+ QString::number(session->mtp().mainDcId()));

	// The distinction worth making: configured is not the same as carrying the traffic.
	const auto &proxy = Core::App().settings().proxy();
	if (!proxy.isEnabled()) {
		lines.append(u"Прямое соединение, прокси не используется."_q);
	} else if (proxy.isSystem()) {
		lines.append(u"Используется системный прокси."_q);
	} else {
		const auto selected = proxy.selected();
		if (selected.type == MTP::ProxyData::Type::None
			|| selected.host.isEmpty()) {
			lines.append(
				u"Прокси включён, но сервер не выбран — трафик идёт напрямую."_q);
		} else {
			lines.append(u"Прокси: "_q
				+ selected.host
				+ u":"_q
				+ QString::number(selected.port));
		}
	}

	Ui::show(Ui::MakeInformBox({
		.text = lines.join(u"\n"_q),
		.title = u"Соединение"_q,
	}));
}

} // namespace DarkGram::AccountTools
