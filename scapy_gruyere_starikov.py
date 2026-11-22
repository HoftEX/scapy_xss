#!/usr/bin/env python3
# Скрипт для домашнего задания: Scapy + XSS на Google Gruyere.
# Умеет снимать HTTP-трафик в pcap и разбирать сохранённый файл.

import argparse
import gzip
import re
import zlib
from urllib.parse import parse_qsl, unquote, urlsplit

from scapy.all import IP, Raw, TCP, rdpcap, sniff, wrpcap


def capture(args):
    # Тут просто слушаем трафик и складываем пакеты в список.
    packets = []
    print("Слушаю интерфейс", args.iface)
    print("Фильтр:", args.filter)
    print("Открой Gruyere в браузере и делай действия. Ctrl+C остановит запись.")
    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            timeout=args.timeout,
            prn=packets.append,
            store=False,
        )
    except KeyboardInterrupt:
        pass
    wrpcap(args.write, packets)
    print("Сохранено пакетов:", len(packets))
    print("Файл:", args.write)


def reassemble(parts):
    # Склеиваем куски одного соединения по номерам.
    result = b""
    last_seq = None
    for seq, data in sorted(parts):
        if last_seq is not None and seq < last_seq:
            data = data[last_seq - seq:]
            if not data:
                continue
        result += data
        last_seq = seq + len(data)
    return result


def parse_http(data):
    # Делим данные на строку запроса, заголовки и тело.
    if b"\r\n\r\n" not in data:
        return None
    head, body = data.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    start_line = lines[0].decode("latin-1", "replace")
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            key, value = line.split(b":", 1)
            headers[key.decode("latin-1").strip().lower()] = value.decode("latin-1").strip()
    length = headers.get("content-length")
    if length and length.isdigit():
        body = body[: int(length)]
    return start_line, headers, body


def decode_body(headers, body):
    # Если сервер сжал ответ, распаковываем его.
    encoding = headers.get("content-encoding", "").lower()
    if "gzip" in encoding:
        return gzip.decompress(body)
    if "deflate" in encoding:
        try:
            return zlib.decompress(body)
        except zlib.error:
            return zlib.decompress(body, -15)
    return body


def looks_like_xss(value):
    # Простая проверка на теги и обработчики событий.
    return bool(re.search(r"<script\b|on[a-z]+\s*=|javascript\s*:", value, re.I))


def get_payloads(request):
    # Достаём из запроса значения, которые похожи на XSS-пейлоад.
    start_line, headers, body = request
    parts = start_line.split(" ")
    if len(parts) < 2:
        return []
    target = parts[1]
    path = unquote(urlsplit(target).path)
    candidates = []

    # В Gruyere reflected XSS бывает в пути URL после id инстанса.
    path_tail = path.split("/", 2)[-1]
    for value in (path_tail, path):
        if looks_like_xss(value):
            candidates.append(("path", value))

    for name, value in parse_qsl(urlsplit(target).query, keep_blank_values=True):
        if looks_like_xss(value):
            candidates.append((name, value))

    if body:
        text = body.decode("latin-1", "replace")
        if looks_like_xss(text):
            candidates.append(("body", text))

    # Убираем повторы.
    unique = []
    for item in candidates:
        if item not in unique:
            unique.append(item)
    return unique


def analyze(args):
    packets = rdpcap(args.pcap)
    print("Прочитано пакетов:", len(packets))

    # Раскладываем пакеты по соединениям и направлениям.
    flows = {}
    for packet in packets:
        if IP not in packet or TCP not in packet or Raw not in packet:
            continue
        ip = packet[IP]
        tcp = packet[TCP]
        payload = bytes(packet[Raw].load)
        if not payload:
            continue
        a = (ip.src, int(tcp.sport))
        b = (ip.dst, int(tcp.dport))
        key = tuple(sorted((a, b)))
        if key not in flows:
            flows[key] = {"directions": [{}, {}], "time": 0}
        flow = flows[key]
        if flow["time"] == 0:
            flow["time"] = float(packet.time)
        index = 0 if a == key[0] else 1
        seq = int(tcp.seq)
        if seq not in flow["directions"][index]:
            flow["directions"][index][seq] = []
        flow["directions"][index][seq].append(payload)

    transactions = []
    for flow in flows.values():
        streams = []
        for direction in flow["directions"]:
            parts = []
            for seq, chunks in direction.items():
                parts.append((seq, b"".join(chunks)))
            streams.append(reassemble(parts))

        requests = []
        responses = []
        for stream in streams:
            if not stream:
                continue
            if stream.startswith(b"HTTP/"):
                parsed = parse_http(stream)
                if parsed:
                    responses.append(parsed)
            elif stream.startswith(
                (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")
            ):
                parsed = parse_http(stream)
                if parsed:
                    requests.append(parsed)

        for i, request in enumerate(requests):
            response = responses[i] if i < len(responses) else None
            transactions.append((request, response, flow["time"]))

    transactions.sort(key=lambda item: item[2])
    print("HTTP-транзакций:", len(transactions))
    print()

    payloads = []
    for number, (request, response, _) in enumerate(transactions, 1):
        start_line, headers, body = request
        method, target = start_line.split(" ")[:2]
        host = headers.get("host", "?")
        print(f"=== {number}. {method} http://{host}{target} ===")
        print("Заголовки запроса:")
        for key, value in headers.items():
            print("   ", key + ":", value)
        if body:
            print("Тело запроса:", body[:300])
        print()

        if response is None:
            print("Ответ не найден")
            print()
        else:
            status_line, resp_headers, resp_body = response
            decoded = decode_body(resp_headers, resp_body)
            print("Ответ:", status_line)
            for key, value in resp_headers.items():
                print("   ", key + ":", value)
            if "gzip" in resp_headers.get("content-encoding", "").lower():
                print("gzip:", len(resp_body), "байт сжато,", len(decoded), "после распаковки")
            text = decoded.decode("latin-1", "replace")
            limit = 5000 if args.full else 300
            print("Тело ответа:")
            print(text[:limit])
            if len(text) > limit:
                print("... показано", limit, "из", len(text))
            print()

        for name, payload in get_payloads(request):
            payloads.append((number, name, payload))

    # Проверяем, где сервер вернул пейлоад. Stored XSS мог быть отправлен
    # раньше, поэтому смотрим ответы начиная с запроса-источника.
    print("=" * 50)
    print("Поиск пейлоадов в ответах")
    print("=" * 50)
    hits = 0
    seen = set()
    for number, (request, response, _) in enumerate(transactions, 1):
        if response is None:
            continue
        text = decode_body(response[1], response[2]).decode("latin-1", "replace")
        for origin, name, payload in payloads:
            if origin > number:
                continue
            key = (name, payload)
            if key in seen:
                continue
            if payload in text:
                seen.add(key)
                hits += 1
                pos = text.find(payload)
                print(f"Пейлоад из запроса {origin} найден в ответе {number}")
                print("   ", payload)
                print("   ...", text[max(0, pos - 120):pos + len(payload) + 120], "...")
                print()
    print("Найдено отражений:", hits)


def main():
    parser = argparse.ArgumentParser(description="Scapy и XSS на Google Gruyere")
    sub = parser.add_subparsers(dest="command", required=True)

    sniff_parser = sub.add_parser("sniff", help="снять трафик в pcap")
    sniff_parser.add_argument("-i", "--iface", default="enp4s0")
    sniff_parser.add_argument("-t", "--timeout", type=int, default=60)
    sniff_parser.add_argument("-w", "--write", default="traffic.pcap")
    sniff_parser.add_argument("--filter", default="tcp port 80 and host google-gruyere.appspot.com")

    analyze_parser = sub.add_parser("analyze", help="разобрать готовый pcap")
    analyze_parser.add_argument("pcap")
    analyze_parser.add_argument("--full", action="store_true", help="печатать тело ответа целиком")

    args = parser.parse_args()
    if args.command == "sniff":
        capture(args)
    else:
        analyze(args)


if __name__ == "__main__":
    main()
