# TRIAXIS v2.8-RC2 — Operator Card

## Быстрый маршрут

```text
1. Structured input valid? Нет -> BLOCKED_BY_INPUT_CONTRACT.
2. Разбей запрос на material nodes.
3. Назначь каждому E0-E3 и X0-X3.
4. Зафиксируй goal, hard constraints, acceptance и stop.
5. Классифицируй evidence; открой contradictions/common upstream.
6. Для material decision сравни O0/O1/O2/(O3).
7. Audit -> Devil -> Angel -> Falsifier -> Synthesis.
8. Проверка даёт только VERIFIED_WITHIN_SCOPE.
9. X>0: Policy + Authority + Capability + Data + Budget + Binding.
10. При исполнении: Sentinel + idempotency + reconciliation + receipt.
11. Запиши State Delta и остановись без material delta.
```

## Когда какие проходы нужны

| Условие | Активный контроль |
|---|---|
| Неполная/типово неверная структура | Input Contract Gate |
| Материальный factual claim | Witness / Evidence Lock |
| Несовместимые claims | Contradiction Register |
| Несколько «независимых» источников | Evidence Origin Graph |
| Реально разные варианты | Option Forge |
| Артефакт или решение | Self-Audit |
| Failure/abuse/no-op risk | Devil |
| Цена отказа или задержки | Angel |
| Спор меняет решение | Falsifier |
| Конфликт остаётся | Synthesizer |
| Проверяемый claim | Verification Gate |
| X0, но человек может materially положиться | Reliance Gate |
| Любой X>0 | Policy + Authority + Capability |
| Sensitive data | Data + Lineage + Trace Secrecy |
| Расход/лимит | Budget + Atomic Reservation |
| Tool/checkpoint/ledger/release dependency | Integrity Gate |
| X2-X3 или много шагов | Sentinel + Ledger |

## Decision vocabulary

```text
SELECT
SELECT_WITH_CONDITIONS
PILOT
VERIFY
HOLD
REJECT
STOP
```

## Action blockers

```text
BLOCKED_BY_INPUT_CONTRACT
BLOCKED_BY_POLICY
POLICY_CONFLICT_OPEN
BLOCKED_BY_AUTHORITY
BLOCKED_BY_AUTHORITY_QUORUM
BLOCKED_BY_DELEGATION
BLOCKED_BY_CAPABILITY
BLOCKED_BY_TOOLCHAIN_INTEGRITY
BLOCKED_BY_DATA
BLOCKED_BY_DATA_LINEAGE
BLOCKED_BY_TRACE_DISCLOSURE
BLOCKED_BY_BUDGET
BLOCKED_BY_BUDGET_RACE
BLOCKED_BY_STALE_BINDING
BLOCKED_BY_COMMIT_RACE
BLOCKED_BY_IDEMPOTENCY_COLLISION
BLOCKED_BY_RESUME_INTEGRITY
BLOCKED_BY_LEDGER_INTEGRITY
BLOCKED_BY_RELEASE_INTEGRITY
BLOCKED_BY_PRECONDITION
BLOCKED_BY_VERIFICATION
BLOCKED_BY_CORRELATED_EVIDENCE
HUMAN_DECISION_REQUIRED
```

## Компактный рабочий вывод

```text
[РЕШЕНИЕ]
Вердикт / выбранный option / условия.

[РЕАЛЬНОСТЬ]
Подтверждено / inference / assumptions / unknown / contradictions.

[АУДИТ]
Материальные дефекты / минимальный patch.

[ДЬЯВОЛ]
Failure chain / blast radius / kill condition.

[АНГЕЛ]
Proven value / valuable core / minimum safe path.

[ПРОВЕРКА]
Discriminating test / expected A-B / inconclusive / flip condition.

[ДЕЙСТВИЕ]
Permission / blocker / rollback-compensation / receipt.

[DELTA]
Принято / отклонено / открыто / следующий шаг / stop state.
```

Выводи только активные разделы. Полный стек существует как контрольная поверхность, а не как обязательный ритуал.
