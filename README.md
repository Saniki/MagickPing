# MagickPing
Реализация скрытой передачи файлов через служебный протокол ICMP на языке Python 3
## Описание файлов
server.py - сервер данной реализации

client.py - клиент

new_ping.py - настройки и алгоритм сбора, отправки и приема пакетов
### Изменение настроек
В файле new_ping.py можно настроить размер отправляемого пакета, порт, по которому будет производится передача и время ожидания запросов ECHO_REPLY

Исходные значения

```
PACKAGE_SIZE = 40768
PORT = 31337
TIMEOUT = 10
```

Уровень логирования изменяется в файлах server.py и client.py для сервера и клиента соответственно

### Запуск сервера

Исполнять с правами суперпользователя

Остановка сервера нажатием Ctrl+C

Пример запуска сервера

`sudo python3 ./server.py`

### Запуск клиента

Исполнять с правами суперпользователя

Остановка клиента нажатием Ctrl+C

**Аргументы клиента:**
```
'-f', '--file' - имя файла, который хотим отправить
'-a', '--address' - адрес на которй хотим отправить
'-c', '--cypher' - включить/выключить шифрование
```
Пример запуска

`sudo python3 ./client.py -f file.app -a localhost`
