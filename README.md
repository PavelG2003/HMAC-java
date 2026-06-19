# HMAC Java

Минимальный REST-сервис для подписи и проверки сообщений по HMAC-SHA256.

## Требования

- JDK 11 или новее.
- Зависимости уже лежат в `lib`: Gson и JUnit 5.

## Конфигурация

Файл `config.json`:

```json
{
  "hmacAlg": "SHA256",
  "secret": "base64-secret",
  "listenPort": 8080,
  "maxMsgSizeBytes": 1048576
}
```

`secret` хранится в обычном base64 и должен содержать не менее 32 байт после декодирования.

Сгенерировать новый секрет можно так:

```bash
java -cp "out;lib/*" ru.yandex.practicum.ServerHMAC rotate-secret config.json
```

## Сборка и запуск

```bash
javac -encoding UTF-8 -cp "lib/*" -d out src/ru/yandex/practicum/*.java
java -cp "out;lib/*" ru.yandex.practicum.ServerHMAC --config config.json
```

## API

Подписать сообщение:

```bash
curl -sS -X POST http://localhost:8080/sign \
  -H "Content-Type: application/json" \
  -d "{\"msg\":\"hello\"}"
```

Ответ:

```json
{"signature":"base64url-without-padding"}
```

Проверить подпись:

```bash
curl -sS -X POST http://localhost:8080/verify \
  -H "Content-Type: application/json" \
  -d "{\"msg\":\"hello\",\"signature\":\"<signature-from-sign>\"}"
```

Ответ:

```json
{"ok":true}
```

Ошибки возвращаются в JSON:

```json
{"error":"invalid_signature_format"}
```

Основные коды: `invalid_json`, `invalid_msg`, `invalid_signature_format`, `payload_too_large`,
`unsupported_media_type`, `internal`.

## Ограничения учебной реализации

HMAC-SHA256 подтверждает целостность сообщения и то, что отправитель знает общий секрет. Это не
асимметричная электронная подпись: здесь нет сертификатов, временных меток, цепочек доверия и
юридической неотказуемости. Сообщение не шифруется, поэтому содержимое остается открытым.

Сервис не пишет секрет и полные входные данные в логи. Для сравнения подписей используется
`MessageDigest.isEqual`.
