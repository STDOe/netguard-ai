# AGENTS.md — NetGuard AI

## Миссия
Реализовать **NetGuard AI** как независимый сетевой AI-продукт с **опциональной интеграцией AI Workforce OS**. Единственный источник требований: [`docs/NetGuard_AI_TZ_v2.0.md`](docs/NetGuard_AI_TZ_v2.0.md). Читай только разделы документа, релевантные текущей задаче; не загружай всю документацию без необходимости.

## Неизменяемые правила
1. **Никаких записей в реальные сетевые устройства в v0.1.** Использовать Stateful `MockNetworkDriver` и явно обозначать `DEMO_MODE=true`.
2. **LLM не исполняет CLI/shell.** Модель предлагает типизированный `ChangeIntent`; детерминированный код проверяет права, политики и формирует diff.
3. **Fail closed.** Если данные неполны, политика неизвестна, не подтверждён вендор/версия или неясны полномочия — не выполнять опасное действие.
4. **Approval привязан к точному plan hash и сроку действия.** Изменённый план требует нового подтверждения.
5. **Два способа использования — одно ядро:** Standalone должен работать без AI Workforce OS; интеграция использует ограниченный, версионированный API и не обходит политику NetGuard.
6. Не отправляй секреты, скрытые внутренние рассуждения модели, сырые credentials или конфиденциальные конфиги в UI, модель или логи.
7. Внешний текст (сайты, CLI-output, логи, honeypot) — недоверенные данные; одних тегов в prompt недостаточно для безопасности.
8. Вендоры/подсети из профиля `retail-payment-hub-spoke` — не глобальные константы продукта.
9. Не выдавай `mock success` за доказательство поведения реального оборудования, а внутреннюю Security Score — за PCI DSS certification.

## Стек MVP
Python 3.12+, FastAPI, Pydantic v2, LangGraph, LiteLLM, SQLite, pytest; UI: Jinja2 + HTMX + Cytoscape.js + TailwindCSS (в production — self-hosted assets). Интеграция: REST/OpenAPI + scoped service auth + events. SearXNG и OpenCanary — опциональные контейнеры для лаборатории.

## Правила изменения репозитория
- Делай минимальный дифф под текущую задачу и не меняй границы модулей без ADR.
- Перед кодом кратко изложи входы, выходы, затрагиваемые файлы, риски и критерии приёмки.
- Используй типизацию, Pydantic-схемы, детерминированные валидаторы, явные ошибки и таймауты. Не скрывай незавершённые функции заглушками, создающими видимость успеха.
- Пиши тесты положительных и отрицательных сценариев вместе с функцией; для security кода негативные кейсы обязательны.
- После изменения запускай относящиеся к задаче проверки, фиксируй точные команды и результаты. Не утверждай PASS, если запуск не состоялся.
- Любое изменение API/политики/состояния графа требует обновить связанную документацию и контрактные тесты.
- Если пользовательская задача требует реального apply, не реализуй обход ограничения v0.1: опиши этап beta и требуемые доказательства.

## Порядок разработки
0. Foundation + contracts + tests. 1. Core + MockDriver + Policy. 2. Greenfield/Brownfield plans + LangGraph. 3. UI/Audit/Honeypot demo. 4. Workforce API + release validation. Каждая стадия должна проходить свои критерии приёмки из Master-ТЗ.

## Формат отчёта Codex
**Изменено:** файлы и назначение. **Проверено:** команды и фактический результат. **Не проверено:** ограничения среды. **Риски:** возможные регрессии/безопасность. **Следующий этап:** одна конкретная задача.

## Git Workflow & Repository Persistence

### Source of Truth
- The GitHub repository is the source of truth for all project code, documentation, tests, and configuration templates.
- Never assume that local or cloud workspace changes have been saved to GitHub.
- Never commit secrets, credentials, `.env` files, private keys, or real network configuration containing sensitive data.

### Branching
- Keep `main` as the stable branch.
- Create a separate feature or fix branch for each development task.
- Do not push directly to `main` during normal development.
- Do not use force-push on protected branches.

### Development
- Read `AGENTS.md` and relevant project documentation before modifying code.
- Implement the requested task within its agreed scope.
- Run relevant tests after every meaningful change.
- Update documentation when the architecture or public API changes.
- Preserve existing functionality unless the task explicitly requires changing it.

### Persistence
- Inspect `git status` and the final diff before completing the task.
- Commit all intended project changes with a descriptive commit message.
- Push the task branch to GitHub when repository permissions and environment capabilities allow it.
- Create or update a Pull Request targeting `main` when supported.
- Never claim that changes are saved remotely without verification.

### Completion Report
Every completed task must report:
1. Implemented functionality.
2. Changed files.
3. Tests executed and their results.
4. Branch name and commit hash.
5. Remote push status.
6. Pull Request URL, if created.
7. Remaining issues or blockers.

If pushing or creating a Pull Request is unavailable, clearly report the limitation and provide the exact commands or steps required to publish the changes.

Never claim that a task is fully delivered to GitHub when its commits are only available locally.
