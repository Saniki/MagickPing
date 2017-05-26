import struct
import socket
import time
import select
import hashlib

# Настраиваемые значения: размер пакета, используемый порт, время ожиданя REPLY
PACKAGE_SIZE = 40768
PORT = 31337
TIMEOUT = 10

# Значения стандарта ICMP
ICMP_HEADER_FMT = '!BBHHH'
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_CODE = 0

# Неизменимые константы
DATA_INFO = 'iii'
DATA_SIZE = PACKAGE_SIZE - struct.calcsize(DATA_INFO) - 28
MAX_ICMP_NUMBER = 2**16 - 1
KEY = [i for i in range(0, DATA_SIZE)]

timer = time.time


def md5_checksum(file_path):
    """
    Подсчет md5 контрольной суммы
    :param file_path: файл для которого считаем контрольную сумму
    :return: контрольная сумма
    """
    with open(file_path, 'rb') as fh:
        m = hashlib.md5()
        while True:
            data = fh.read(8192)
            if not data:
                break
            m.update(data)
        return m.hexdigest()


def package_checksum(source):
    """
    Подсчет контрольной суммы по алгоритму RFC1071, взят готовый вариант
    :param source: пакет, контрольную сумму которого нужно посчитать
    :return: контрольная сумма
    """

    check_sum = 0
    count = 0
    while count < len(source) - 1:
        tmp = source[count + 1] * 256 + source[count]
        check_sum += tmp
        check_sum &= 0xFFFFFFFF
        count += 2

    if len(source) % 2:
        check_sum += source[len(source) - 1]
        check_sum &= 0xFFFFFFFF

    check_sum = (check_sum >> 16) + (check_sum & 0xFFFF)
    check_sum = ~check_sum & 0xFFFF
    check_sum = (check_sum >> 8 & 0x00FF) | (check_sum << 8 & 0xFF00)
    socket.htons(check_sum)

    return check_sum


def create_package(data, package_number, icmp_id, icmp_type):
    """
    Создаем пакет с данными
    :param data: данные, которые надо упаковать
    :param package_number: номер пакета
    :param icmp_id: ID в заголовок ICMP пакета
    :param icmp_type: номер запроса
    :return: package: пакет, готовый к отправке
    """
    # icmp_header: type(1), code(1), checksum(2), id(2), package_number (2) = 8 байт

    # По алгоритму создания хэш-суммы, сначала с пустой хэш-суммой
    icmp_number = package_number % MAX_ICMP_NUMBER
    data = struct.pack(DATA_INFO, icmp_type, package_number, len(data)) + data
    header = struct.pack(ICMP_HEADER_FMT, icmp_type, ICMP_CODE, 0, icmp_id, icmp_number)

    # Дополняем данные случайным символом, можно менять
    data += (PACKAGE_SIZE - len(header) - len(data)) * 'a'.encode()

    # Потом с пересчитанной хэш-суммой
    package = header + data
    checksum = package_checksum(package)
    header = struct.pack(ICMP_HEADER_FMT, icmp_type, ICMP_CODE, checksum, icmp_id, icmp_number)
    package = header + data

    return package


def reply(sock, addr, client_id, package_number):
    """
    Ответ на запрос, имитирует ECHO_REPLY
    :param sock: сокет
    :param addr: адрес назначения
    :param client_id: ID клиента, отправившего запрос
    :param package_number: номер пакета
    """
    addr = socket.gethostbyname(addr)
    package = create_package(bytes(0), package_number, client_id, ICMP_ECHO_REPLY)
    sock.sendto(package, (addr, PORT))


def waiting(sock, waiting_package_number):
    """
    Ожидаем пакета с типом ECHO_REPLY
    :param sock: сокет
    :param waiting_package_number: ожидаемый номер пакета
    :return: True - если ответ получен
    """
    while True:
        select_timeout = select.select([sock], [], [], TIMEOUT)

        if not select_timeout[0]:
            return False

        package, address = sock.recvfrom(PACKAGE_SIZE)
        (sock_type,) = struct.unpack('i', package[28:28+struct.calcsize('i')])

        if sock_type == ICMP_ECHO_REPLY:
            (received_package,) = struct.unpack('i', package[32:32+struct.calcsize('i')])

            if waiting_package_number == received_package:
                return True


def send_package(sock, addr, icmp_id, data, package_number):
    """
    Отправляем пакет с собранными данными, имитируя пинг
    :param sock: сокет клиента
    :param addr: адрес назначения
    :param icmp_id: в header ICMP пакета
    :param data: отправляемые данные
    :param package_number: номер пакета
    :return:
    """
    addr = socket.gethostbyname(addr)
    package = create_package(data, package_number, icmp_id, ICMP_ECHO_REQUEST)

    flag = True
    while flag:  # ждем ответа, если не получаем, посылаем пакет еще раз
        sock.sendto(package, (addr, PORT))
        flag = not waiting(sock, package_number)


def receive_package(sock, req_id, count):
    """
    Получение пакета, проверка и ответ ECHO_REPLY
    :param sock: сокет
    :param req_id: ожидаемый ID
    :param count: счетчик уже полученных пакетов
    :return: котреж (адрес клиента, номер пакета, данные)
    """
    while True:
        select_timeout = select.select([sock], [], [], TIMEOUT)  # ждем пока на сокет начнут приходить данные

        if not select_timeout[0]:
            return None, None, None

        package, address = sock.recvfrom(PACKAGE_SIZE)
        # распаковываем часть моего header(а), в которой лежит тип пакета
        (sock_type,) = struct.unpack('i', package[28:28+struct.calcsize('i')])

        if sock_type == ICMP_ECHO_REQUEST:
            info_size = struct.calcsize('ii')
            data = package[32:]
            (package_number, len_data), data = struct.unpack('ii', data[:info_size]), data[info_size:]

            try:
                # если нам пришел пакет, который нам уже приходил, принимаем заново
                if package_number != 0 and package_number <= count[address[0]]:
                    continue
            except KeyError:
                pass

            data = data[:len_data]
            reply(sock, address[0], req_id, package_number)
            return address, package_number, data
