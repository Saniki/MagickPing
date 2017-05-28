import socket
import new_ping
import os
import datetime
import signal
import logging
import struct

logging.basicConfig(format=u'%(levelname)-8s [%(asctime)s] %(message)s', level=logging.DEBUG, filename=u'server.log')


# Обработка CTRL+C
def signal_handler(signal, frame):
    print("\nОстановка сервера.")
    sock.close()
    logging.info("Остановка сервера пользователем.")
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

print("СТАРТ СЕРВЕРА")
logging.info("СТАРТ СЕРВЕРА")

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
sock.bind(('', new_ping.PORT))

addr_file = {}  # словарь с парами адрес : полный путь до файла
packet_count = {}  # счетчик принятых пакетов
cypher_mode = {}  # использование шифрования для файлов
file_names = {}  # имя файла без пути

recv_file = None
ID = 1
while True:
    addr, package_number, data = new_ping.receive_package(sock, ID, packet_count)

    if not addr:
        continue

    # первый пакет содержит режим шифрования и имя отправляемого клиентом файла
    if package_number == 1:
        # директории которые надо создать
        temp = datetime.datetime.now().strftime("%d-%m-%Y")
        path = (addr[0], temp, datetime.datetime.now().strftime("%H:%M"))
        tmp = ''  # последовательное создание директорий, если директория уже есть то переходим к следующей
        for dir_name in path:
            if len(tmp):
                tmp += '/' + dir_name
            else:
                tmp = dir_name
            try:
                os.mkdir(tmp)
                logging.debug("Создана папка: %s" % tmp)
                os.chmod(tmp, 0o777)
            except FileExistsError:
                pass

        # считываем режим шифрования
        (info,) = struct.unpack('b', data[:struct.calcsize('b')])
        if info:
            cypher_mode[addr[0]] = True
        else:
            cypher_mode[addr[0]] = False

        data = data[struct.calcsize('b'):]
        file_name = data.decode().split('/')[-1]
        file_names[addr[0]] = file_name
        logging.debug("Начало приема файла: %s, от клиента: %s" % (file_name, addr[0]))
        print("Начало приема файла: %s, от клиента: %s" % (file_name, addr[0]))

        # имя файла с учетом директорий, в которых он должен находиться
        file_name = tmp + '/' + file_name
        file_names[addr[0]] = file_name
        recv_file = open(file_name, 'wb')
        os.chmod(file_name, 0o777)

        addr_file[addr[0]] = recv_file
        packet_count[addr[0]] = 1
        continue

    if addr_file.get(addr[0]) and package_number > 1:
        packet_count[addr[0]] += 1
        logging.debug("%d пакет получен, от клиента: %s" % (packet_count[addr[0]], addr[0]))
        if cypher_mode[addr[0]]:
            data = [a ^ b for (a, b) in zip(data, new_ping.KEY)]
            data = bytes(data)
        addr_file[addr[0]].write(data)
        continue

    if addr_file.get(addr[0]) and package_number == 0:
        addr_file[addr[0]].close()
        logging.info("Получен файл: %s, количество пакетов: %d" % (addr[0], packet_count[addr[0]]))
        print("Получен файл: %s, количество пакетов: %d" % (addr[0], packet_count[addr[0]]))
        new_ping.send_package(sock, addr[0], ID, new_ping.md5_checksum(file_names[addr[0]]).encode(), 0)

        packet_count.pop(addr[0])
        addr_file.pop(addr[0])
        cypher_mode.pop(addr[0])
        file_names.pop(addr[0])
