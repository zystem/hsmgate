# Криптографический аудит hsmgate

Дата: 21 октября 2026. Снимок: `e766cb79916a5d0095be7ae1f6f1fa0fb9bd6c5c`.
Проверку выполнил ассистент по запросу автора проекта. Объект — реализация и границы протоколов; аппаратная генерация ключей, RNG карты, side channels и формальное доказательство безопасности не проверены.

## Вывод

**В проверенных операциях ECIES не обнаружено нарушения базовых свойств ECDH/HKDF/AEAD. Однако в обвязке найдены воспроизводимые нарушения разделения ключей и привязки ciphertext к логическому ключу.** Они позволяют получить MAC-ключ или расшифровать чужой логический ciphertext, если конфигурация повторно использует один private key под разными разрешениями. Такая конфигурация проходит Validate.

Есть также гонка памяти производного MAC-ключа при включённом cache и возможность принять SigV4-запрос, подпись которого не покрывает тело. Это проблемы реализации и протокольного связывания, а не взлом P-256 или XChaCha20-Poly1305. При независимых физических ключах и отключённом MAC cache соответствующие условия атак отсутствуют; отсутствие этих условий в реальном deployment здесь не установлено.

Подробные находки, рекомендации и журналы: [основной отчёт](REPORT.ru.md).

## 1. Что именно защищает сервис

В ECIES master private key остаётся в PKCS#11; ECDH shared secret возвращается в процесс, где выполняются KDF и AEAD. Plaintext также находится в памяти сервиса. В KMS key_agreement shared secret намеренно передаётся клиенту. В MAC-режиме производный симметричный ключ находится в heap сервиса и при включённом cache хранится до TTL. В режиме Sign подпись производится токеном, но корректность hardware nonce зависит от карты/драйвера.

Нельзя объединять эти роли только потому, что исходный private key «не экспортируется»: доступ к ECDH с выбранной точкой может раскрыть материал других протоколов на том же private key. Именно это показал PoC MAC-ключа. В threat model роль derive сильнее обычного context-scoped decrypt.

## 2. ECIES и KDF

Проверены `internal/scheme/ecies/ecies.go`, обе server faces и `internal/keyops`.

```text
Q = dG                 master public key
E = eG                 fresh ephemeral P-256 key
Z = ECDH(e, Q)         при открытии ECDH(d, E)
fp = SHA256(DER-SPKI(Q))
salt = "cinim/kek/v1"
info = "cinim/kek/v1|" || fp_hex || "|" || E_hex
K = HKDF-SHA256(Z, salt, info, 32)
C = XChaCha20-Poly1305(K, nonce24, plaintext, AAD)
```

Ручная реализация `deriveKey` выполняет HKDF-Extract через HMAC(salt, Z) и первый блок Expand через HMAC(PRK, info || 0x01). Для 32-байтного результата SHA-256 одного блока достаточно. **128 случайных дифференциальных случаев совпали с `crypto/hkdf.Key`**. Это проверка эквивалентности реализации, не доказательство всей схемы. Конструкция сопоставлена с [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869).

Salt не обязан быть секретным или случайным для каждого сообщения; в этой реализации он служит постоянным разделителем. Уникальность рабочего контекста обеспечивают fresh ephemeral key и info с public keys. В info сейчас нет логического имени/version ключа, что имеет значение для cross-key binding.

Fingerprint проверен независимо: хеш результата `x509.MarshalPKIXPublicKey` совпадает с ручным SPKI prefix. Fingerprint — идентификатор публичного ключа, не секрет и не подпись владельца. Его присутствие в ciphertext само по себе не подтверждает происхождение сообщения.

P-256 public keys создаются/проверяются через `crypto/ecdh`. В Unwrap ephemeral point проверяется до передачи в Derive; в KMS DeriveSharedSecret DER SPKI разбирается и ограничивается P-256. У этой кривой cofactor 1, поэтому после корректной проверки точки отдельная защита от малого подгруппового cofactor не требуется. Проверено использование соответствующих [Go ECDH API](https://pkg.go.dev/crypto/ecdh), а не сам ассемблер/реализация кривой внутри toolchain.

PKCS11 `Point` проверяет размер/префикс представления, но не доказывает атрибуты и provenance реального master key. Проверка ожидаемого fingerprint и provisioning остаются обязательной частью доверия к держателю.

## 3. AEAD, randomness и формат

Используется `chacha20poly1305.NewX`: ключ 32 байта, nonce 24 байта, tag 16 байт. Ephemeral key и nonce берутся из `crypto/rand`; фиксированного nonce или счётчика с reset на restart в коде нет. Выбор большого случайного nonce соответствует назначению [NewX](https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305#NewX).

В дополнительном тесте 256 encryptions дали разные ephemeral points и nonce. Для каждой encryption изменение каждого байта nonce/ciphertext/tag отвергалось при открытии. Всего проверено 13 568 одно-битовых мутаций body. Существующие Nim vectors и штатные round-trip/negative tests также прошли. Это не статистическая сертификация источника энтропии.

Для случайного 192-битного nonce вероятность коллизии при n независимых nonce приближённо n(n−1)/2^193. В ECIES дополнительно меняется ephemeral-derived key. Тем не менее безопасность должна опираться на исправный OS RNG и уникальность key/nonce pair, а не на отсутствие совпадений в выборке.

Формат ecies1 включает tag формата, fp, ephemeral point и nonce/ciphertext/tag. Публичные поля участвуют в выборе/деривации ключа, а данные защищены AEAD. Но внешние KMS blob fields `HGK1 + name + version` не включены в AEAD AAD/KDF. В context mode AAD состоит только из канонизированного EncryptionContext. **Подмена name между логическими ключами с одинаковым материалом и AAD воспроизведена** (CR-02).

Формат раскрывает длину plaintext с постоянными накладными расходами, fingerprint и связность ключевых версий. Он не даёт аутентификацию отправителя: любой владелец public key способен создать новый корректный ciphertext. Это нормальное свойство public-key encryption, которое нельзя заменять утверждением «ciphertext создан авторизованным клиентом».

Схема не даёт forward secrecy относительно последующей компрометации master private key: сохранённые ephemeral public keys позволяют открыть старые ciphertext с этим ключом. Для долгосрочного envelope storage это ожидаемо; защита старых данных требует rotation/deletion и отдельной модели хранения ключевых версий.

## 4. AAD и разграничение tenants

Fixed mode использует configured fixed string либо `openbao/seal/v1|<name>`; context mode Transit принимает точные decoded bytes, KMS сериализует map как отсортированные `name=value` строки. KMS отвергает '=' и newline в имени и newline в значении, благодаря чему у принятой map нет очевидной неоднозначности разделителей. Сортировка даёт одинаковый AAD при разном порядке полей.

Префиксы остаются префиксами: `tenant=a` разрешает и `tenant=alice`, если это одна строка. Необходимы разделитель/точное сравнение согласно политике приложения. KMS key-level и grant-level ограничения могут удовлетворяться разными строками map; это полезно для условий вида `purpose=dek` AND `tenant=alice`, но не является произвольным IAM condition language. В отчёте это не объявлено самостоятельным tenant bypass.

Криптографическая изоляция логических ключей в context mode сейчас зависит от неповторения private key. Одни только разные имена и grants её не создают. Для нового wire version рекомендуется AEAD binding сериализованного domain/algorithm/logical-key-id/key-version/context. Для legacy ecies1 следует оставить явный путь совместимости: молчаливое изменение AAD нарушит существующие ciphertext и Nim vectors.

## 5. Производный MAC-ключ

```text
P = deterministic point from SHA256("hsmgate/mac/v1/point" || counter)
Z = ECDH(master_private, P)
Kmac = HKDF-SHA256(Z, "hsmgate/mac/v1", "mac|" || fp, 32)
tag = HMAC-SHA256(Kmac, message)
```

Точка строится через try-and-increment x, square root уравнения P-256 и выбор чётного y. Независимый расчёт Python SHA-256 + арифметика поля воспроизвёл committed point; counter равен 0. Результат: [mac-point-reference.json](raw/mac-point-reference.json). Публичные переменные не требуют constant-time арифметики для сокрытия секрета: master scalar в этой функции отсутствует.

Критически важно, что P не получена как публично известный scalar × G: иначе общий секрет вычислялся бы из master public key. В данной процедуре такой scalar не задан. Однако проверка «P != G» сама по себе не доказывает неизвестность discrete log, а воспроизведение seed не является формальным доказательством NUMS/security construction.

Это собственная derivation-конструкция, не реализация hash-to-curve suite [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html). Для нового формата предпочтительны стандартизованный mapping/domain separation и отдельный review. Variable-time try-and-increment с публичной фиксированной строкой здесь не раскрывает master key; нельзя механически переносить на этот случай предупреждение о secret-dependent timing.

HMAC-SHA256 используется с полным 32-байтным tag, VerifyMac сравнивает через `hmac.Equal`. Криптографически это разумные примитивы при секретном Kmac. **CR-01 нарушает предпосылку секретности Kmac**, когда другой alias того же physical key допускает DeriveSharedSecret(P). Кэш также возвращает mutable backing slice наружу mutex; отдельный race-test подтвердил CR-03.

MAC cache выключен по умолчанию, но при включении превращает on-token root в извлекаемый software MAC secret на TTL. Это осознанный компромисс производительности; даже корректная реализация cache не сохраняет свойство «каждый MAC требует карту».

## 6. ECDSA

KMS Sign принимает RAW (SHA-256 внутри сервиса) либо DIGEST ровно 32 байта, ограничивает алгоритм ECDSA_SHA_256 и проверяет sign grant. PKCS11 использует CKM_ECDSA над digest и преобразует raw r||s из 64 байт в ASN.1 DER; двойного SHA-256 в PKCS11 пути не обнаружено. Verify использует Go `ecdsa.VerifyASN1` и проверяет согласованный digest. RAW/DIGEST семантика сопоставлена с [AWS Sign](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html).

Правильность hardware ECDSA зависит от nonce k: повторный/предсказуемый k может раскрыть private key. Тестовый soft backend использует Go SignASN1, fake PKCS11 проверяет формат и результат, но эти тесты **не проверяют RNG реальной карты**. Здесь не выполнялась серия аппаратных подписей, проверка повторения r, fault injection или timing analysis. ECDSA low-S normalization отсутствует; это не делает обычную проверку неверной, но подпись не следует использовать как уникальный идентификатор события.

В приложении один key usage обозначается как signing-only; фактическое разделение по физическому ключу неполно (CR-01). Предпочтительны отдельные master keys и hardware attributes CKA_SIGN/CKA_DERIVE под назначение. Проверка attributes и non-extractability реальных ключей в аудит не входила.

## 7. SigV4 и TLS

Проверены credential scope, timestamp/skew, обязательные host/date/target, canonical query/headers, HMAC derivation и constant-time signature comparison. Штатный known-answer test и black-box официальный Go SDK прошли. В обычном hashed-payload режиме изменение body ломает подпись.

Но `X-Amz-Content-Sha256: UNSIGNED-PAYLOAD` разрешён verifier. Для специально подписанного такого запроса PoC заменил body без изменения Authorization, и оба body прошли Verify (CR-04). Для KMS Sign/Decrypt/MAC эта возможность не нужна и должна быть отвергнута. Наличие аналогичного режима в отдельных AWS-сервисах не означает, что он безопасен для любой API. Сопоставление алгоритма выполнено с [AWS SigV4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html).

TLS защищает запрос в сети; CR-04 не является доказанным обходом TLS или генерацией SigV4 без secret. Для атаки нужен доступ к уже корректно подписанному unsigned-payload request и возможность предъявить его от допустимого источника. В режиме no_cert ограничения предъявления слабее, поскольку client certificate не требуется. Обычный full-payload AWS SDK request этим PoC не превращён в unsigned.

Временной интервал SigV4 допускает replay в пределах 5 минут; отсутствие replay cache задокументировано. Поэтому не надо считать Sign/GenerateMac гарантированно однократными операциями. Механизм nonce/idempotency, если он нужен приложению, должен быть отдельным.

Сервер использует TLS 1.3 и повторную проверку клиентской цепочки на запросах. При наличии no_cert TLS client cert становится optional для всего listener, а права проверяются каждым face. Старое обобщение «все запросы защищены mTLS» для текущего проекта уже неверно. Подлинные no_cert credentials и allow_from являются самостоятельной границей доступа; source IP за NAT/proxy не равен идентичности клиента.

## 8. Секреты, журнал и внешняя среда

Ни Go heap zeroing, ни mlock/core policy в одном unit не гарантируют удаления всех копий plaintext, private material soft backend, PIN string, SigV4 secret и KDF state. В ECIES Z/PRK/derived key не зануляются последовательно. Работа HSM защищает извлечение root при исправной hardware policy, но не секреты, уже возвращённые в процесс.

Sign и MAC записывают 48-битный prefix digest сообщения в audit. Хеш сообщения не обязательно публичен: для низкоэнтропийного словаря читатель audit может проверить кандидатов. Рекомендуется явно объявить эти поля metadata с соответствующей чувствительностью либо сделать message correlation opt-in. Audit не должен описывать их как безусловно безопасные только из-за хеширования.

Рабочая конфигурация provisioning, entropy источников SigV4 secrets, PKCS11 module/firmware и атрибуты master keys не представлены как отдельные проверенные артефакты. Для завершённого hardware crypto review нужны inventory ролей/FP, подтверждение RNG и non-extractability, запрет cross-role alias, unplug/recovery и проверка разных моделей карт. Экспериментальный `tools/scard-spike` с AES-CBC/CMAC не является production backend; его CBC с нулевым IV не был ошибочно приписан сервису и на реальной карте не запускался.

## Критерии приёмки

1. Любое совпадение physical public key/fingerprint между несовместимыми ролями отклоняется независимо от label/CKA_ID case/path/token alias; для недоступной карты используется закреплённый inventory и проверка при появлении.
2. Новый ciphertext cryptographically bound к canonical logical key id/version/domain; legacy поведение явно ограничено совместимостью.
3. MAC cache возвращает private copy под mutex; race PoC становится зелёным без race warning и сохраняет правильный MAC при reload/expiry.
4. SigV4 UNSIGNED-PAYLOAD отклоняется; известные SDK clients продолжают проходить тесты.
5. Hardware evidence подтверждает соответствие private/public key, разделение CKA_SIGN/CKA_DERIVE и качество ECDSA nonce generation. Пока этого нет, итог нельзя интерпретировать как сертификацию криптомодуля.
