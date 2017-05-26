import socket
import argparse
import sys
import new_ping
import os
import signal
import logging
import struct

logging.basicConfig(format=u'%(levelname)-8s [%(asctime)s] %(message)s', level=logging.DEBUG, filename=u'client.log')


# Обработка CTRL+C
def signal_handler(signal, frame):
    print("\nОстановка клиента.")
    logging.info("Остановка клиента пользователем.")
    exit(0)


# Парсер аргументов командной строки
def create_cmd_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', required=True, type=argparse.FileType(mode='rb'))
    parser.add_argument('-a', '--address', required=True)
    parser.add_argument('-c', '--cypher', action='store_const', const=True)

    return parser

signal.signal(signal.SIGINT, signal_handler)

if __name__ == '__main__':
    # считываем аргументы, открываем файл и сокет для отправки ICMP пакетов
    p = create_cmd_parser()
    arguments = p.parse_args(sys.argv[1:])
    file = arguments.file
    file_name = file.name
    file_size = os.stat(file_name).st_size
    server_addr = arguments.address
    client_id = 1
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    # первый пакет содержит имя файла и режим шифрования (1 - вкл, 0 - выкл)
    package_number = 1
    data = file_name.encode()
    if arguments.cypher:
        data = struct.pack('b', 1) + data
    else:
        data = struct.pack('b', 0) + data
    logging.debug("Начало отправки файла по адресу %s %s" % (file_name, server_addr))
    new_ping.send_package(sock, server_addr, client_id, data, package_number)

    print('Начало отправки')

    sent_part = 0  # размер уже отправленной части
    tmp = 0           # параметр для вывода информации в консоль

    # цикл отправки файла, считываем часть, шифруем если надо и отправляем
    while True:
        data = file.read(new_ping.DATA_SIZE)
        if arguments.cypher:
            data = [a ^ b for (a, b) in zip(data, new_ping.KEY)]
            data = bytes(data)
        if not data:
            break

        sent_part += len(data)
        package_number += 1
        new_ping.send_package(sock, server_addr, client_id, data, package_number)

        # выводим информацию в консоль через каждый процент отправленных данных
        if ((sent_part / file_size * 100) - (tmp / file_size * 100)) > 1:
            tmp = sent_part
            print('Отправлено: %.2f %%' % (sent_part / file_size * 100))
            logging.info('Отправлено: %.2f %%' % (sent_part / file_size * 100))

    # последний пакет имеет номер 0, чтобы сервер мог его распознать
    new_ping.send_package(sock, server_addr, client_id, bytes(0), package_number=0)
    logging.debug("Отправлено пакетов: %d" % package_number)
    print("Отправлено пакетов:", package_number)
    file.close()

    # проверяем MD5-хэш пришедший от сервера
    client_address, package_number, checksum = new_ping.receive_package(sock, client_id, {})
    if checksum and new_ping.md5_checksum(file_name) != checksum.decode():
        logging.warning("MD5-хэш не совпал. Ошибка при передаче.")
        print("MD5-хэш не совпал. Ошибка при передаче.")
    else:
        print("MD5-хэш совпал")
    sock.close()

