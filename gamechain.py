#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GameChain — система учёта и передачи игровых предметов на основе технологии блокчейн.

Демонстрационная программа: показывает, как с помощью хеширования SHA-256
и цепочки блоков можно обнаруживать несанкционированные изменения
данных учётных записей пользователей.

Запуск:
    python3 gamechain.py          — интерактивное меню
    python3 gamechain.py --demo   — автоматическая демонстрация всех сценариев

Используется только стандартная библиотека Python 3.8+.
"""

import copy
import hashlib
import json
import os
import sys
import time
from datetime import datetime

DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gamechain_data.json")

# Сложность «доказательства работы»: хеш блока должен начинаться с N нулей.
# Это делает пересчёт всей цепочки злоумышленником дорогим.
DIFFICULTY = 4

# Типы операций, которые записываются в блокчейн
OP_GENESIS = "GENESIS"
OP_REGISTER = "REGISTER_USER"
OP_UPDATE = "UPDATE_USER"
OP_ADD_ITEM = "ADD_ITEM"
OP_TRANSFER = "TRANSFER_ITEM"

# Каталог игровых предметов (тот же, что и на сайте index.html): название → редкость
ITEMS = {
    "Медный меч": "обычный", "Железный меч": "необычный", "Ледяной клинок": "редкий",
    "Меч дракона": "легендарный", "Медная кирка": "обычный", "Золотая кирка": "редкий",
    "Посох огня": "эпический", "Посох льда": "редкий", "Посох тьмы": "эпический",
    "Деревянный щит": "обычный", "Щит паладина": "эпический", "Железный шлем": "необычный",
    "Золотой шлем": "редкий", "Зелье здоровья": "обычный", "Зелье маны": "обычный",
    "Зелье удачи": "необычный", "Рубин": "редкий", "Изумруд": "редкий",
    "Аметист": "эпический", "Алмаз": "легендарный",
}


# ─────────────────────────── Оформление вывода ───────────────────────────

class C:
    """ANSI-цвета для терминала."""
    if sys.stdout.isatty() and os.name != "nt" or os.environ.get("FORCE_COLOR"):
        RED, GREEN, YELLOW, BLUE, CYAN, GRAY, BOLD, END = (
            "\033[91m", "\033[92m", "\033[93m", "\033[94m",
            "\033[96m", "\033[90m", "\033[1m", "\033[0m",
        )
    else:
        RED = GREEN = YELLOW = BLUE = CYAN = GRAY = BOLD = END = ""


def ok(msg):
    print(f"{C.GREEN}✔ {msg}{C.END}")


def bad(msg):
    print(f"{C.RED}✘ {msg}{C.END}")


def info(msg):
    print(f"{C.CYAN}{msg}{C.END}")


def title(msg):
    line = "═" * 70
    print(f"\n{C.BOLD}{C.BLUE}{line}\n  {msg}\n{line}{C.END}")


# ─────────────────────────────── Хеширование ──────────────────────────────

def sha256(text: str) -> str:
    """SHA-256 от строки, результат — 64 шестнадцатеричных символа."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical(obj) -> str:
    """Каноническое JSON-представление: одинаковые данные → одинаковая строка → одинаковый хеш."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def hash_password(password: str, salt: str) -> str:
    """Пароль никогда не хранится в открытом виде — только хеш с «солью»."""
    return sha256(salt + password)


def record_hash(user: dict) -> str:
    """Отпечаток (хеш) учётной записи пользователя."""
    return sha256(canonical(user))


# ─────────────────────────────────── Блок ─────────────────────────────────

class Block:
    def __init__(self, index, operation, data, prev_hash, timestamp=None, nonce=0, hash_=None):
        self.index = index
        self.timestamp = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.operation = operation
        self.data = data
        self.prev_hash = prev_hash
        self.nonce = nonce
        self.hash = hash_ or self.compute_hash()

    def header(self) -> dict:
        """Всё содержимое блока, кроме самого хеша."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "operation": self.operation,
            "data": self.data,
            "prev_hash": self.prev_hash,
            "nonce": self.nonce,
        }

    def compute_hash(self) -> str:
        return sha256(canonical(self.header()))

    def mine(self, difficulty=DIFFICULTY):
        """
        Подбор nonce, пока хеш не начнётся с нужного числа нулей (Proof-of-Work).

        Ускорение («мидстейт»): канонический JSON блока делится на части до и после значения nonce.
        Начало одинаково во всех попытках, поэтому хешируется один раз, а на каждой попытке
        копируется готовое состояние SHA-256 (hashlib .copy()) и досчитывается только хвост.
        Сложность проверяется по первым 4 байтам хеша: d hex-нулей = старшие 4·d бит равны нулю.
        """
        self.nonce = 0
        text = canonical(self.header())
        at = text.rindex('"nonce":0')
        prefix = hashlib.sha256(text[:at + 8].encode("utf-8"))
        suffix = text[at + 9:].encode("utf-8")
        shift = 32 - 4 * difficulty
        nonce = 0
        while True:
            h = prefix.copy()
            h.update(str(nonce).encode() + suffix)
            digest = h.digest()
            if int.from_bytes(digest[:4], "big") >> shift == 0:
                break
            nonce += 1
        self.nonce, self.hash = nonce, digest.hex()
        return self.hash

    def to_dict(self):
        d = self.header()
        d["hash"] = self.hash
        return d

    @staticmethod
    def from_dict(d):
        return Block(d["index"], d["operation"], d["data"], d["prev_hash"],
                     d["timestamp"], d["nonce"], d["hash"])


# ──────────────────────────────── Блокчейн ────────────────────────────────

class Blockchain:
    def __init__(self):
        genesis = Block(0, OP_GENESIS, {"message": "GameChain genesis block"}, "0" * 64)
        genesis.mine()
        self.chain = [genesis]

    @property
    def last(self) -> Block:
        return self.chain[-1]

    def add(self, operation, data) -> Block:
        block = Block(len(self.chain), operation, data, self.last.hash)
        t0 = time.time()
        block.mine()
        info(f"  ⛏  Блок #{block.index} добыт за {time.time() - t0:.2f} с "
             f"(nonce={block.nonce}), хеш {block.hash}")
        self.chain.append(block)
        return block

    def validate(self):
        """
        Проверка целостности цепочки. Возвращает список нарушений: пары (номер блока, описание).
        Для каждого блока проверяется:
          1) хеш, записанный в блоке, совпадает с пересчитанным хешем содержимого;
          2) хеш удовлетворяет условию Proof-of-Work;
          3) поле prev_hash совпадает с хешем предыдущего блока.
        """
        problems = []
        target = "0" * DIFFICULTY
        for i, block in enumerate(self.chain):
            real = block.compute_hash()
            if real != block.hash:
                problems.append((i,
                    f"Блок #{i} ({block.operation}): содержимое изменено — "
                    f"записан хеш {block.hash}, а фактический {real}"))
            elif not block.hash.startswith(target):
                problems.append((i,
                    f"Блок #{i} ({block.operation}): хеш пересчитан без Proof-of-Work "
                    f"({block.hash} не начинается с {target})"))
            if i > 0 and block.prev_hash != self.chain[i - 1].hash:
                problems.append((i,
                    f"Блок #{i}: разрыв цепочки — prev_hash {block.prev_hash} "
                    f"≠ хеш блока #{i - 1} {self.chain[i - 1].hash}"))
        return problems

    def replay(self):
        """
        Восстановление «эталонного» состояния учётных записей по истории блоков.
        Блокчейн — источник истины: база данных должна с ним совпадать.

        Заодно каждый блок сверяется с восстановленным состоянием:
          • отпечаток записи в блоке должен совпадать с хешем записи после применения блока —
            иначе блок создан на основе подменённых данных («отмывание» взлома);
          • операция должна быть возможной — например, нельзя передать предмет,
            которого у игрока по истории не было.
        Возвращает (users, problems), где problems — пары (номер блока, описание).
        """
        users, problems, tainted = {}, [], set()

        def check(i, b, name, recorded):
            # Для каждой учётной записи сообщаем только о первом расхождении:
            # все последующие блоки этой записи построены на тех же подменённых данных
            if name in tainted or recorded == record_hash(users[name]):
                return
            tainted.add(name)
            problems.append((i, f"Блок #{i} ({b.operation}): отпечаток «{name}» не совпадает "
                                f"с восстановленным состоянием — блок создан на основе подменённых данных"))

        def need(name):
            if name not in users:
                raise ValueError(f"пользователь «{name}» не зарегистрирован")
            return users[name]

        for i, b in enumerate(self.chain[1:], 1):
            d = b.data
            try:
                if b.operation == OP_REGISTER:
                    if d["username"] in users:
                        raise ValueError(f"пользователь «{d['username']}» уже зарегистрирован")
                    users[d["username"]] = copy.deepcopy(d["user"])
                    check(i, b, d["username"], d["record_hash"])
                elif b.operation == OP_UPDATE:
                    u = need(d["username"])
                    if d["username"] not in tainted and u.get(d["field"]) != d["old"]:
                        raise ValueError(f"в блоке старое значение {d['field']} = {d['old']!r}, "
                                         f"а по истории {u.get(d['field'])!r}")
                    u[d["field"]] = d["new"]
                    check(i, b, d["username"], d["record_hash"])
                elif b.operation == OP_ADD_ITEM:
                    need(d["username"])["items"].append(d["item"])
                    check(i, b, d["username"], d["record_hash"])
                elif b.operation == OP_TRANSFER:
                    s, r = need(d["from"]), need(d["to"])
                    if d["item"] not in s["items"]:
                        raise ValueError(f"у игрока {d['from']} не было предмета «{d['item']}»")
                    s["items"].remove(d["item"])
                    r["items"].append(d["item"])
                    check(i, b, d["from"], d["from_hash"])
                    check(i, b, d["to"], d["to_hash"])
            except (ValueError, KeyError, TypeError) as e:
                problems.append((i, f"Блок #{i} ({b.operation}): невозможная операция — {e}"))
        return users, problems

    def history_of(self, username):
        return [b for b in self.chain[1:] if username in (
            b.data.get("username"), b.data.get("from"), b.data.get("to"))]


# ───────────────────────────── Система GameChain ──────────────────────────

class GameChain:
    """
    Учётные записи хранятся в «базе данных» (словарь users), как в обычной игре.
    Каждое изменение дополнительно фиксируется блоком в блокчейне вместе
    с SHA-256 отпечатком новой версии записи.
    """

    EDITABLE_FIELDS = ("nickname", "email", "level", "gold")

    def __init__(self):
        self.chain = Blockchain()
        self.users = {}

    # ---------- операции пользователя ----------

    def register(self, username, nickname, email, password):
        self._require_integrity()
        if username in self.users:
            raise ValueError(f"Пользователь «{username}» уже существует")
        salt = sha256(username + str(time.time()))[:16]
        user = {
            "username": username,
            "nickname": nickname,
            "email": email,
            "salt": salt,
            "password_hash": hash_password(password, salt),
            "level": 1,
            "gold": 100,
            "items": [],
        }
        self.users[username] = user
        self.chain.add(OP_REGISTER, {"username": username, "user": copy.deepcopy(user),
                                     "record_hash": record_hash(user)})
        ok(f"Пользователь «{username}» зарегистрирован")

    def update(self, username, field, value):
        self._require_integrity()
        user = self._get(username)
        if field not in self.EDITABLE_FIELDS:
            raise ValueError(f"Поле «{field}» нельзя изменять. Доступно: {', '.join(self.EDITABLE_FIELDS)}")
        if field in ("level", "gold"):
            value = int(value)
        old = user[field]
        user[field] = value
        self.chain.add(OP_UPDATE, {"username": username, "field": field, "old": old,
                                   "new": value, "record_hash": record_hash(user)})
        ok(f"{username}.{field}: {old!r} → {value!r}")

    def add_item(self, username, item):
        self._require_integrity()
        user = self._get(username)
        user["items"].append(item)
        self.chain.add(OP_ADD_ITEM, {"username": username, "item": item,
                                     "record_hash": record_hash(user)})
        ok(f"Предмет «{item}» выдан игроку {username}")

    def transfer(self, sender, receiver, item):
        self._require_integrity()
        s, r = self._get(sender), self._get(receiver)
        if item not in s["items"]:
            raise ValueError(f"У игрока {sender} нет предмета «{item}»")
        s["items"].remove(item)
        r["items"].append(item)
        self.chain.add(OP_TRANSFER, {"from": sender, "to": receiver, "item": item,
                                     "from_hash": record_hash(s), "to_hash": record_hash(r)})
        ok(f"Предмет «{item}» передан: {sender} → {receiver}")

    def login(self, username, password):
        user = self._get(username)
        return hash_password(password, user["salt"]) == user["password_hash"]

    def _get(self, username):
        if username not in self.users:
            raise ValueError(f"Пользователь «{username}» не найден")
        return self.users[username]

    # ---------- проверка целостности ----------

    def audit(self):
        """
        Полная проверка: сама цепочка, каждый блок по восстановленному состоянию
        и соответствие базы данных блокчейну.
        Возвращает (список нарушений, номер первого испорченного блока или None).
        """
        block_problems = self.chain.validate()
        db_problems = []

        if not block_problems:
            expected_users, block_problems = self.chain.replay()
            for name in sorted(set(self.users) | set(expected_users)):
                if name not in expected_users:
                    db_problems.append(f"Учётная запись «{name}» есть в базе, но не зарегистрирована в блокчейне")
                    continue
                if name not in self.users:
                    db_problems.append(f"Учётная запись «{name}» удалена из базы, хотя есть в блокчейне")
                    continue
                actual, expected = record_hash(self.users[name]), record_hash(expected_users[name])
                if actual != expected:
                    diff = [f"{k}: в базе {self.users[name].get(k)!r}, по блокчейну {v!r}"
                            for k, v in expected_users[name].items() if self.users[name].get(k) != v]
                    db_problems.append(
                        f"Учётная запись «{name}» подменена! SHA-256 записи {actual} "
                        f"≠ восстановленной по блокчейну {expected}\n      "
                        + "\n      ".join(diff))

        first_bad = min((i for i, _ in block_problems), default=None)
        return [text for _, text in block_problems] + db_problems, first_bad

    def _require_integrity(self):
        """Пока есть нарушения, новые операции запрещены — иначе они «отмоют» подменённые данные."""
        problems, _ = self.audit()
        if problems:
            raise ValueError(f"Операция заблокирована: обнаружены нарушения целостности ({len(problems)}). "
                             f"Сначала восстановите базу из блокчейна (п. 11).")

    def recover(self):
        """
        Восстановление по блокчейну: цепочка обрезается до последнего корректного блока,
        а база данных собирается заново из истории блоков.
        Возвращает число отброшенных блоков.
        """
        _, first_bad = self.audit()
        removed = 0
        if first_bad is not None:
            removed = len(self.chain.chain) - max(first_bad, 1)
            self.chain.chain = self.chain.chain[:max(first_bad, 1)]
            if first_bad == 0:                           # испорчен сам genesis — начинаем заново
                self.chain = Blockchain()
        self.users, _ = self.chain.replay()
        return removed

    def verify(self, verbose=True):
        """Полная проверка с выводом отчёта. Возвращает список нарушений."""
        problems, _ = self.audit()

        if verbose:
            title("ПРОВЕРКА ЦЕЛОСТНОСТИ")
            print(f"Блоков в цепочке: {len(self.chain.chain)}, учётных записей: {len(self.users)}")
            if problems:
                bad(f"Обнаружено нарушений: {len(problems)}")
                for p in problems:
                    print(f"  {C.RED}• {p}{C.END}")
            else:
                ok("Цепочка цела, все учётные записи совпадают с блокчейном")
        return problems

    # ---------- хранение ----------

    def save(self, path=DATA_FILE):
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"users": self.users,
                       "blockchain": [b.to_dict() for b in self.chain.chain]},
                      f, ensure_ascii=False, indent=2)

    @staticmethod
    def load(path=DATA_FILE):
        gc = GameChain()
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                raw = json.load(f)
            gc.users = raw["users"]
            gc.chain.chain = [Block.from_dict(d) for d in raw["blockchain"]]
        return gc

    # ---------- вывод ----------

    def print_chain(self):
        title("БЛОКЧЕЙН")
        for b in self.chain.chain:
            valid = b.compute_hash() == b.hash
            mark = f"{C.GREEN}✔{C.END}" if valid else f"{C.RED}✘{C.END}"
            print(f"{mark} {C.BOLD}Блок #{b.index}{C.END}  {b.timestamp}  {C.YELLOW}{b.operation}{C.END}")
            print(f"    данные:    {describe(b)}")
            print(f"    prev_hash: {C.GRAY}{b.prev_hash}{C.END}")
            print(f"    hash:      {b.hash}")
            print(f"    nonce:     {b.nonce}")

    def print_users(self):
        title("УЧЁТНЫЕ ЗАПИСИ (база данных)")
        if not self.users:
            print("Пользователей пока нет")
        for u in self.users.values():
            print(f"{C.BOLD}{u['username']}{C.END} ({u['nickname']}), {u['email']}, "
                  f"уровень {u['level']}, золото {u['gold']}")
            print(f"    предметы: {', '.join(u['items']) or '—'}")
            print(f"    SHA-256 записи: {C.GRAY}{record_hash(u)}{C.END}")

    def print_history(self, username):
        title(f"ИСТОРИЯ ИЗМЕНЕНИЙ: {username}")
        for b in self.chain.history_of(username):
            print(f"  #{b.index:<3} {b.timestamp}  {b.operation:<14} {describe(b)}")


def describe(b: Block) -> str:
    d = b.data
    if b.operation == OP_GENESIS:
        return d["message"]
    if b.operation == OP_REGISTER:
        u = d["user"]
        return f"регистрация {u['username']} ({u['nickname']}, {u['email']})"
    if b.operation == OP_UPDATE:
        return f"{d['username']}.{d['field']}: {d['old']!r} → {d['new']!r}"
    if b.operation == OP_ADD_ITEM:
        return f"{d['username']} получил «{d['item']}»"
    if b.operation == OP_TRANSFER:
        return f"«{d['item']}»: {d['from']} → {d['to']}"
    return str(d)


# ──────────────────────────── Сценарии атак ───────────────────────────────

def show_hash_change(label, before, after):
    """Печатает старый и новый хеш; изменившиеся символы нового хеша выделены красным."""
    changed = sum(a != b for a, b in zip(before, after))
    marked = "".join(f"{C.RED}{C.BOLD}{b}{C.END}" if a != b else f"{C.GRAY}{b}{C.END}" for a, b in zip(before, after))
    print(f"    {label}: было  {C.GREEN}{before}{C.END}")
    print(f"    {' ' * len(label)}  стало {marked}")
    print(f"    {' ' * len(label)}  {C.YELLOW}изменилось {changed} из {len(after)} символов — лавинный эффект{C.END}")


def attack_edit_database(gc: GameChain, username, field, value):
    """Атака 1: злоумышленник напрямую правит базу данных (без записи в блокчейн)."""
    user = gc._get(username)
    if field in ("level", "gold"):
        value = int(value)
    before = record_hash(user)
    if field == "items":
        user["items"].append(value)
    else:
        user[field] = value
    bad(f"АТАКА: в базе данных изменено {username}.{field} = {value!r} (в обход блокчейна)")
    show_hash_change("SHA-256 записи", before, record_hash(user))


def attack_edit_old_block(gc: GameChain, index, rehash=False):
    """
    Атака 2: злоумышленник меняет старую запись в истории.
    rehash=False — просто правит данные блока;
    rehash=True  — правит данные и пересчитывает хеш этого блока (без PoW),
                   пытаясь скрыть следы.
    """
    if not 0 < index < len(gc.chain.chain):
        raise ValueError("Неверный номер блока")
    b = gc.chain.chain[index]
    d = b.data
    old_hash = b.hash
    if b.operation == OP_REGISTER:
        d["user"]["email"] = "hacker@evil.com"
        what = "email при регистрации → hacker@evil.com"
    elif b.operation == OP_UPDATE:
        d["new"] = 999999 if isinstance(d["new"], int) else "HACKED"
        what = f"новое значение поля {d['field']} → {d['new']!r}"
    elif b.operation == OP_ADD_ITEM:
        d["item"] = "Легендарный меч (подделка)"
        what = "выданный предмет → «Легендарный меч (подделка)»"
    else:
        d["to"], d["from"] = d["from"], d["to"]
        what = "отправитель и получатель поменяны местами"
    if rehash:
        b.hash = b.compute_hash()
    bad(f"АТАКА: изменён блок #{index}: {what}" + (" + хеш блока пересчитан" if rehash else ""))
    show_hash_change("хеш блока по содержимому", old_hash, b.compute_hash())
    if not rehash:
        info("    (в блоке по-прежнему записан старый хеш — несовпадение выдаст подделку)")
    elif index + 1 < len(gc.chain.chain):
        info(f"    (блок #{index + 1} по-прежнему ссылается на старый хеш — цепочка разорвана)")


# ─────────────────────────── Автоматическая демонстрация ──────────────────

def pause(interactive):
    if interactive:
        input(f"{C.GRAY}  … Enter — продолжить{C.END}")


def run_demo(interactive=False):
    title("GameChain — АВТОМАТИЧЕСКАЯ ДЕМОНСТРАЦИЯ")

    info("\nШаг 1. Регистрируем игроков (каждая регистрация — новый блок)")
    gc = GameChain()
    gc.register("alice", "Alice_Knight", "alice@mail.ru", "qwerty123")
    gc.register("bob", "BobTheMage", "bob@mail.ru", "pass456")

    info("\nШаг 2. Игровые события: предметы, обмен, изменение профиля")
    gc.add_item("alice", "Меч дракона")
    gc.add_item("alice", "Щит паладина")
    gc.add_item("bob", "Посох огня")
    gc.transfer("alice", "bob", "Щит паладина")
    gc.update("bob", "gold", 250)
    gc.update("alice", "email", "alice.knight@mail.ru")

    info("\nПроверка входа: пароль хранится только как SHA-256 хеш с солью")
    print(f"  login(alice, 'qwerty123') → {gc.login('alice', 'qwerty123')}")
    print(f"  login(alice, 'wrong')     → {gc.login('alice', 'wrong')}")

    gc.print_users()
    gc.print_history("alice")
    gc.verify()
    pause(interactive)

    original = copy.deepcopy(gc)

    title("СЦЕНАРИЙ 1: подмена данных учётной записи в базе данных")
    attack_edit_database(gc, "bob", "gold", 1_000_000)
    gc.verify()
    pause(interactive)

    gc = copy.deepcopy(original)
    title("СЦЕНАРИЙ 2: изменение старой записи в истории (блок #3)")
    attack_edit_old_block(gc, 3)
    gc.verify()
    pause(interactive)

    gc = copy.deepcopy(original)
    title("СЦЕНАРИЙ 3: изменение старой записи + пересчёт её хеша")
    attack_edit_old_block(gc, 3, rehash=True)
    gc.verify()
    pause(interactive)

    gc = copy.deepcopy(original)
    title("СЦЕНАРИЙ 4: подмена email в базе + удаление чужой записи")
    attack_edit_database(gc, "alice", "email", "hacker@evil.com")
    del gc.users["bob"]
    bad("АТАКА: учётная запись bob удалена из базы данных")
    gc.verify()
    pause(interactive)

    gc = copy.deepcopy(original)
    title("СЦЕНАРИЙ 5: дюп предмета и попытка «отмыть» его передачей")
    attack_edit_database(gc, "bob", "items", "Меч дракона")
    info("Злоумышленник пытается передать продублированный меч, чтобы подмена ушла в блокчейн:")
    try:
        gc.transfer("bob", "alice", "Меч дракона")
    except ValueError as e:
        bad(str(e))
    info("Даже если такой блок всё-таки попадёт в цепочку (например, в обход системы),")
    info("проверка по восстановленному состоянию его обнаружит:")
    gc._require_integrity = lambda: None             # имитируем обход блокировки
    gc.transfer("bob", "alice", "Меч дракона")
    del gc._require_integrity
    gc.verify()
    info("\nВосстанавливаем базу из блокчейна:")
    removed = gc.recover()
    ok(f"База восстановлена, отброшено блоков, созданных после взлома: {removed}")
    gc.verify()

    title("ИТОГ")
    print("• Изменение данных в базе в обход блокчейна → не совпадает SHA-256 записи.")
    print("• Изменение старого блока → хеш блока не совпадает с его содержимым.")
    print("• Пересчёт хеша изменённого блока → разрыв связи prev_hash со следующим блоком")
    print("  и нарушение Proof-of-Work; чтобы скрыть следы, пришлось бы заново «добыть»")
    print("  все последующие блоки, что вычислительно дорого.")
    print("• Новые операции после взлома блокируются, а блок, созданный на основе")
    print("  подменённых данных, не совпадает с состоянием, восстановленным по истории.")


# ─────────────────────────────── Меню ─────────────────────────────────────

MENU = f"""
{C.BOLD}GameChain — учёт и передача игровых предметов на блокчейне{C.END}
  1. Зарегистрировать пользователя
  2. Изменить данные пользователя
  3. Выдать предмет
  4. Передать предмет
  5. Показать пользователей
  6. Показать блокчейн
  7. История изменений пользователя
  8. Проверить целостность
  9. Смоделировать атаку
 10. Автоматическая демонстрация
 11. Восстановить базу из блокчейна
  0. Выход
"""


def ask(prompt):
    return input(f"{C.YELLOW}{prompt}{C.END}").strip()


def choose_item():
    """Выбор предмета из каталога по номеру."""
    names = list(ITEMS)
    for i, name in enumerate(names, 1):
        print(f"  {i:>2}. {name:<16} {C.GRAY}{ITEMS[name]}{C.END}")
    choice = ask("Номер предмета: ")
    if not choice.isdigit() or not 1 <= int(choice) <= len(names):
        raise ValueError("Нет предмета с таким номером")
    return names[int(choice) - 1]


def choose_own_item(gc, username):
    """Выбор предмета из инвентаря игрока по номеру."""
    items = list(dict.fromkeys(gc._get(username)["items"]))
    if not items:
        raise ValueError(f"У игрока {username} нет предметов")
    for i, name in enumerate(items, 1):
        print(f"  {i:>2}. {name}")
    choice = ask("Номер предмета: ")
    if not choice.isdigit() or not 1 <= int(choice) <= len(items):
        raise ValueError("Нет предмета с таким номером")
    return items[int(choice) - 1]


def attack_menu(gc):
    print("  1. Подменить данные учётной записи в базе (gold, level, email, nickname, items)")
    print("  2. Изменить старый блок")
    print("  3. Изменить старый блок и пересчитать его хеш")
    choice = ask("Выбор: ")
    if choice == "1":
        attack_edit_database(gc, ask("Пользователь: "), ask("Поле: "), ask("Новое значение: "))
    elif choice in ("2", "3"):
        attack_edit_old_block(gc, int(ask(f"Номер блока (1–{len(gc.chain.chain) - 1}): ")),
                              rehash=choice == "3")
    info("Запустите «8. Проверить целостность», чтобы увидеть, как атака обнаруживается.")


def main():
    if "--demo" in sys.argv:
        run_demo()
        return

    gc = GameChain.load()
    info(f"Данные: {DATA_FILE}")
    info("Совет: можно вручную изменить этот файл в редакторе и затем выполнить проверку (п. 8).")

    while True:
        print(MENU)
        choice = ask("Выберите пункт: ")
        try:
            if choice == "1":
                gc.register(ask("Логин: "), ask("Никнейм: "), ask("Email: "), ask("Пароль: "))
            elif choice == "2":
                gc.update(ask("Пользователь: "), ask(f"Поле ({', '.join(GameChain.EDITABLE_FIELDS)}): "),
                          ask("Новое значение: "))
            elif choice == "3":
                gc._require_integrity()
                username = ask("Пользователь: ")
                gc._get(username)
                gc.add_item(username, choose_item())
            elif choice == "4":
                gc._require_integrity()
                sender = ask("От кого: ")
                item = choose_own_item(gc, sender)
                gc.transfer(sender, ask("Кому: "), item)
            elif choice == "5":
                gc.print_users()
            elif choice == "6":
                gc.print_chain()
            elif choice == "7":
                gc.print_history(ask("Пользователь: "))
            elif choice == "8":
                gc = GameChain.load()  # перечитываем файл — вдруг его изменили вручную
                gc.verify()
            elif choice == "9":
                attack_menu(gc)
            elif choice == "10":
                run_demo(interactive=True)
            elif choice == "11":
                removed = gc.recover()
                ok(f"База восстановлена по блокчейну, отброшено блоков после взлома: {removed}")
                gc.verify()
            elif choice == "0":
                break
            else:
                continue
            if choice not in ("8", "10"):
                gc.save()
        except (ValueError, KeyError) as e:
            bad(f"Ошибка: {e}")
        except (EOFError, KeyboardInterrupt):
            break


if __name__ == "__main__":
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print()
