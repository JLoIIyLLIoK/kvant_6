#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
КВАНТ-6 — эмулятор учебной ЭВМ.  Лабораторная работа № 6.

Это ваш рабочий файл. Он уже запускается, но почти ничего не умеет:
в местах, помеченных  TODO, машину предстоит достроить вам.
Порядок работы — по главам задачника (lab6_student.html):

    глава 1  — Reader, load()                  -> python kvant.py info DEMO.kv6
    глава 2  — decode(), disassemble()         -> python kvant.py dis  DEMO.kv6
    глава 3  — wrap32, деление, стек, step()   -> python kvant.py run  DEMO.kv6 --no-limit
    глава 4  — CALL/RET, куча без сборки, PIX  -> экран вашего картриджа
    глава 5  — скрытые команды X1–X3           -> КОД-1
    глава 6  — сборщик мусора                  -> КОД-2 и послание
    глава 7  — (бонус) ускорение               -> python kvant.py bench BENCH.kv6

Проверка себя:   python test_kvant.py        (или  python test_kvant.py 3  — только глава 3)

Всё, что НЕ помечено TODO, — готовые инструменты: командная строка,
сохранение PNG, печать статистики. Их можно не трогать (но читать полезно).
"""

import hashlib
import os
import sys
import time
from dataclasses import dataclass, field

# Чтобы русские буквы нормально печатались в консоли Windows.
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass


# ════════════════════════════════════════════════════════════════════════
#  Ошибки
# ════════════════════════════════════════════════════════════════════════

class LoadError(Exception):
    """Файл не является исправным картриджем."""


class VMError(Exception):
    """Машина остановилась с ошибкой (деление на ноль, пустой стек и т. п.)."""


# ════════════════════════════════════════════════════════════════════════
#  ГЛАВА 1.  Загрузчик
# ════════════════════════════════════════════════════════════════════════

MAGIC = b'KVNT'


@dataclass
class Cartridge:
    """Всё, что загрузчик достал из файла."""
    owner: str                  # номер студенческого владельца
    kind: int                   # 0 — основной, 1 — бенчмарк, 2 — экзаменационный
    heap: int                   # ёмкость кучи в слотах
    nglobals: int               # сколько глобальных переменных G[...]
    entry: int                  # точка входа — адрес первой команды
    consts: list = field(default_factory=list)   # пул строк
    code: bytes = b''           # секция кода
    version: tuple = (1, 0)


class Reader:
    """Читает байты по порядку, как курсор в тексте.

    r = Reader(b'\\x00\\x2A\\xFF')
    r.u16()  -> 42      (два байта, старший вперёд)
    r.u8()   -> 255
    """

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0            # где сейчас курсор

    def take(self, n: int) -> bytes:
        """Вернуть следующие n байтов и сдвинуть курсор.

        Если запрошено отрицательное число байтов или данных недостаточно,
        возбуждается LoadError. При ошибке позиция курсора не меняется.
        """
        if n < 0 or self.pos + n > len(self.data):
            raise LoadError(
                f'Недостаточно байтов: запрошено {n}, доступно {len(self.data) - self.pos}'
            )

        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def u8(self) -> int:
        """1 байт без знака (0…255)."""
        return self.take(1)[0]

    def u16(self) -> int:
        """2 байта без знака, big-endian."""
        return int.from_bytes(self.take(2), 'big')

    def u32(self) -> int:
        """4 байта без знака, big-endian."""
        return int.from_bytes(self.take(4), 'big')


def load(data: bytes) -> Cartridge:
    """Разобрать картридж формата KVNT и проверить его SHA-256."""
    # Хеш занимает последние 32 байта. Файл должен содержать хотя бы
    # сигнатуру и отдельный блок контрольной суммы.
    if len(data) < 4 + 32:
        raise LoadError('Файл слишком короткий: отсутствует заголовок или SHA-256')

    body = data[:-32]
    digest = data[-32:]

    if body[:4] != MAGIC:
        raise LoadError('Неверная сигнатура: ожидалось KVNT')

    expected_digest = hashlib.sha256(body).digest()
    if digest != expected_digest:
        raise LoadError('Контрольная сумма SHA-256 не совпадает: картридж повреждён')

    try:
        r = Reader(body)
        r.take(4)  # сигнатура KVNT уже проверена

        version = (r.u8(), r.u8())

        owner_length = r.u8()
        owner = r.take(owner_length).decode('utf-8')

        kind = r.u8()
        heap = r.u16()
        nglobals = r.u8()
        entry = r.u16()

        const_count = r.u16()
        consts = []
        for _ in range(const_count):
            string_length = r.u16()
            consts.append(r.take(string_length).decode('utf-8'))

        code_length = r.u32()
        code = r.take(code_length)

        # После чтения секции кода курсор должен находиться ровно
        # перед 32-байтовой контрольной суммой (то есть в конце body).
        if r.pos != len(body):
            raise LoadError('Некорректная длина картриджа: после кода остались лишние байты')

        return Cartridge(
            owner=owner,
            kind=kind,
            heap=heap,
            nglobals=nglobals,
            entry=entry,
            consts=consts,
            code=code,
            version=version,
        )

    except LoadError:
        raise
    except UnicodeDecodeError as exc:
        raise LoadError('Строка владельца или пула не является корректным UTF-8') from exc


# ════════════════════════════════════════════════════════════════════════
#  ГЛАВА 2.  Команды и дизассемблер
# ════════════════════════════════════════════════════════════════════════

# Код операции -> (мнемоника, форма операндов).
# Буквы формы:  i — i32 (4 байта со знаком)   b — u8 (1 байт)
#               w — u16 (номер строки/теста)  a — u16 адрес перехода
# Например, CALL имеет форму 'ab': сначала адрес (2 байта), потом n (1 байт).
OPCODES = {
    0x00: ('NOP', ''),     0x01: ('PUSH', 'i'),  0x02: ('POP', ''),
    0x03: ('DUP', ''),     0x04: ('SWAP', ''),
    0x10: ('ADD', ''),     0x11: ('SUB', ''),    0x12: ('MUL', ''),
    0x13: ('DIV', ''),     0x14: ('MOD', ''),    0x15: ('NEG', ''),
    0x18: ('EQ', ''),      0x19: ('LT', ''),     0x1A: ('GT', ''),   0x1B: ('NOT', ''),
    0x20: ('LOAD', 'b'),   0x21: ('STORE', 'b'), 0x22: ('GLOAD', 'b'), 0x23: ('GSTORE', 'b'),
    0x28: ('JMP', 'a'),    0x29: ('JZ', 'a'),    0x2A: ('JNZ', 'a'),
    0x2B: ('CALL', 'ab'),  0x2C: ('RET', ''),    0x2D: ('HALT', ''),
    0x30: ('NEW', ''),     0x31: ('GETF', ''),   0x32: ('SETF', ''),
    0x33: ('LEN', ''),     0x34: ('MEMINFO', 'b'),
    0x38: ('PRINT', ''),   0x39: ('PRINTC', ''), 0x3A: ('PRINTS', 'w'),
    0x3B: ('PIX', ''),     0x3C: ('ASSERT', 'w'),
    0x40: ('X1', ''),      0x41: ('X2', ''),     0x42: ('X3', ''),
}

OPERAND_SIZE = {'i': 4, 'b': 1, 'w': 2, 'a': 2}


def decode(code: bytes, pc: int):
    """Расшифровать одну команду по адресу pc.

    Вернуть кортеж (мнемоника, [операнды], адрес_следующей_команды)
    или None, если такого кода операции нет в OPCODES.

    decode(bytes([0x01, 0, 0, 0, 42]), 0)  ->  ('PUSH', [42], 5)
    decode(bytes([0x2B, 0, 8, 1]), 0)      ->  ('CALL', [8, 1], 4)
    """
    if pc < 0 or pc >= len(code):
        return None

    opcode = code[pc]

    if opcode not in OPCODES:
        return None

    mnemonic, fmt = OPCODES[opcode]

    operands = []
    pos = pc + 1

    for kind in fmt:
        size = OPERAND_SIZE[kind]

        if pos + size > len(code):
            return None

        raw = code[pos:pos + size]

        if kind == 'i':
            value = int.from_bytes(raw, 'big', signed=True)
        else:
            value = int.from_bytes(raw, 'big', signed=False)

        operands.append(value)
        pos += size

    return mnemonic, operands, pos


def disassemble(cart: Cartridge) -> str:
    """Листинг всего кода в формате главы 2.

    L_0008:
      0008  LOAD    0
      0010  JZ      L_0019
      006C  PRINTS  0    ; 'ПРИВЕТ, КВАНТ-6!\\n'

    Метки L_XXXX — у адресов, на которые ведут переходы/вызовы, и у точки входа.
    Неизвестный байт печатается как  ??      0x40  и разбор идёт дальше со следующего байта.
    """

    code = cart.code

    # Первый проход: собираем адреса меток.
    labels = {cart.entry}
    pc = 0

    while pc < len(code):
        result = decode(code, pc)

        if result is None:
            pc += 1
            continue

        mnemonic, operands, next_pc = result

        if mnemonic in ('JMP', 'JZ', 'JNZ', 'CALL'):
            labels.add(operands[0])

        pc = next_pc

    # Второй проход: формируем текст листинга.
    lines = []
    pc = 0

    while pc < len(code):
        # Если текущий адрес является меткой, выводим её.
        if pc in labels:
            label_line = f'L_{pc:04X}:'

            if pc == cart.entry:
                label_line += '    ; точка входа'

            lines.append(label_line)

        result = decode(code, pc)

        # Неизвестная команда: выводим байт и переходим дальше.
        if result is None:
            lines.append(f'  {pc:04X}  ??      0x{code[pc]:02X}')
            pc += 1
            continue

        mnemonic, operands, next_pc = result

        # Формируем операнды.
        if mnemonic in ('JMP', 'JZ', 'JNZ', 'CALL'):
            args = [f'L_{operands[0]:04X}']
            args.extend(str(x) for x in operands[1:])
        else:
            args = [str(x) for x in operands]

        line = f'  {pc:04X}  {mnemonic:<7}'

        if args:
            line += ' ' + ', '.join(args)

        # Для PRINTS показываем соответствующую строку.
        if mnemonic == 'PRINTS':
            line += f'    ; {cart.consts[operands[0]]!r}'

        lines.append(line.rstrip())
        pc = next_pc

    return '\n'.join(lines) + '\n'



# ════════════════════════════════════════════════════════════════════════
#  ГЛАВА 3.  32-битная арифметика «как в Java»
# ════════════════════════════════════════════════════════════════════════

def wrap32(x: int) -> int:
    """Привести целое Python к 32-битному со знаком (отбросить старшие биты).

    wrap32(2**31) -> -2147483648      wrap32(65536 * 65536) -> 0
    """
    x = x & 0xFFFFFFFF

    if x >= 0x80000000:
        x -= 0x100000000

    return x


def java_div(a: int, b: int) -> int:
    """Частное, округлённое К НУЛЮ:  java_div(-7, 2) -> -3   (а -7 // 2 в Python = -4!)."""
    if b == 0:
        raise VMError('деление на ноль')

    result = abs(a) // abs(b)

    if (a < 0) != (b < 0):
        result = -result

    return wrap32(result)


def java_mod(a: int, b: int) -> int:
    """Остаток со знаком делимого:  a - b * java_div(a, b).   java_mod(-7, 2) -> -1."""
    if b == 0:
        raise VMError('деление на ноль')

    return wrap32(a - b * java_div(a, b))


# ════════════════════════════════════════════════════════════════════════
#  ГЛАВА 5.  Скрытые команды
# ════════════════════════════════════════════════════════════════════════
# Каждая скрытая команда — функция f(a, b) -> int, результат в 32 битах.
# Когда разгадаете команду, допишите её сюда, например:
#
#     def x1(a, b):
#         return wrap32(...)
#
#     HIDDEN = {'X1': x1}
#
# Пока команды нет в словаре, машина честно останавливается на ней
# с ошибкой «неизвестная команда 0x40».

HIDDEN = {}


# ════════════════════════════════════════════════════════════════════════
#  ГЛАВЫ 4 и 6.  Куча и сборщик мусора
# ════════════════════════════════════════════════════════════════════════

class HeapObject:
    """Массив в куче «Кванта». Ссылка на него — это сам объект Python."""
    __slots__ = ('items', 'alive', 'marked')

    def __init__(self, n: int, fill=0):
        self.items = [fill] * n     # элементы: числа или ссылки (HeapObject)
        self.alive = True           # False — объект освобождён сборщиком
        self.marked = False         # пометка для сборщика (глава 6)

    def __repr__(self):
        return f'<объект[{len(self.items)}]{"" if self.alive else " освобождён"}>'


class Heap:
    """Учёт памяти. Объект из n элементов занимает n + 1 слот."""

    def __init__(self, capacity: int, no_limit: bool = False):
        self.capacity = capacity
        self.no_limit = no_limit     # True — ёмкость игнорируется, сборки нет
        self.objects = []            # все созданные и ещё не освобождённые объекты
        self.used = 0                # занято слотов
        self.peak = 0                # максимум used за всё время
        self.gc_count = 0            # сколько раз запускалась сборка
        self.allocated = 0           # сколько объектов создано всего
        self.freed = 0               # сколько объектов освобождено всего
        self.log = []                # история для графика: (номер_команды, used, событие)

    def alloc(self, n: int, vm, fill=0) -> HeapObject:
        """Создать объект из n элементов (правила — глава 4, затем глава 6).

        vm передаётся, чтобы сборщик мог спросить у машины корни (vm.roots())
        и номер текущей команды (vm.steps) для графика.
        """
        # TODO 4.3  Проверить n (число, 1…4096), создать HeapObject, обновить
        #           used / peak / allocated, добавить в self.objects,
        #           записать в self.log (vm.steps, self.used, 'alloc').
        # TODO 6.3  Перед созданием: если не no_limit и used + (n+1) > capacity —
        #           self.collect(vm); если места всё равно нет — VMError('OUT OF MEMORY').
        raise NotImplementedError('Глава 4: Heap.alloc')

    def collect(self, vm):
        """Сборка мусора «пометка и очистка» (mark & sweep). Глава 6."""
        # TODO 6.2  1) gc_count += 1, запись в log (vm.steps, used, 'gc_before')
        #           2) пометка: обойти всё достижимое из vm.roots()
        #              (без рекурсии Python — используйте список-«очередь дел»)
        #           3) очистка: непомеченные -> alive = False, вернуть их слоты,
        #              помеченным снять пометку
        #           4) запись в log (vm.steps, used, 'gc_after')
        raise NotImplementedError('Глава 6: Heap.collect')


# ════════════════════════════════════════════════════════════════════════
#  ГЛАВЫ 3–6.  Машина
# ════════════════════════════════════════════════════════════════════════

STACK_LIMIT = 1024
FRAME_LIMIT = 256
NLOCALS = 16


class Frame:
    """Кадр вызова функции."""
    __slots__ = ('locals', 'ret', 'base')

    def __init__(self, ret: int, base: int):
        self.locals = [0] * NLOCALS   # L[0] … L[15]
        self.ret = ret                # адрес возврата
        self.base = base              # «дно»: высота стека в момент входа


class VM:
    def __init__(self, cart: Cartridge, hidden=None, heap_capacity=None,
                 no_limit=False, echo=False, trace=False):
        self.cart = cart
        self.code = cart.code
        self.pc = cart.entry
        self.stack = []                           # стек операндов
        self.frames = [Frame(ret=-1, base=0)]     # кадр главной программы
        self.globals = [0] * cart.nglobals
        cap = cart.heap if heap_capacity is None else heap_capacity
        self.heap = Heap(cap, no_limit)
        self.screen = [[0] * 32 for _ in range(32)]   # screen[y][x]
        self.out = []                             # всё, что напечатала программа
        self.steps = 0
        self.halted = False
        self.echo = echo                          # печатать вывод сразу
        self.trace = trace                        # печатать каждую команду (отладка)
        self.hidden = HIDDEN if hidden is None else hidden
        self.handlers = self._build_handlers()

    # ── готовые инструменты ─────────────────────────────────────────────
    def _build_handlers(self):
        """Таблица диспетчеризации: мнемоника -> метод op_<мнемоника>.

        Метод op_push обрабатывает PUSH, op_add — ADD и т. д. Если метода нет,
        команда считается неизвестной. Скрытые команды берутся из self.hidden.
        """
        table = {}
        for name, _form in OPCODES.values():
            method = getattr(self, 'op_' + name.lower(), None)
            if name in ('X1', 'X2', 'X3'):
                if name in self.hidden:
                    table[name] = self._make_hidden(self.hidden[name])
            elif method is not None:
                table[name] = method
            else:
                table[name] = self._not_yet(name)
        return table

    @staticmethod
    def _not_yet(name):
        def handler(args):
            raise NotImplementedError(f'команда {name} — нет метода op_{name.lower()}')
        return handler

    def _make_hidden(self, f):
        def handler(args):
            b = self.pop_int()
            a = self.pop_int()
            self.push(wrap32(f(a, b)))
        return handler

    def write(self, text: str):
        """Вывод программы (PRINT, PRINTC, PRINTS)."""
        self.out.append(text)
        if self.echo:
            print(text, end='', flush=True)

    def output(self) -> str:
        return ''.join(self.out)

    @property
    def frame(self) -> Frame:
        """Текущий кадр."""
        return self.frames[-1]

    def run(self, max_steps=200_000_000):
        while not self.halted:
            if self.steps >= max_steps:
                raise VMError('слишком много шагов — похоже на бесконечный цикл')
            if self.trace:
                print(self.trace_line(), file=sys.stderr)
            self.step()

    def trace_line(self) -> str:
        d = decode(self.code, self.pc)
        what = '??' if d is None else (d[0] + ' ' + ', '.join(map(str, d[1]))).strip()
        top = ', '.join(_short(v) for v in self.stack[-6:])
        return f'{self.steps:>8}  {self.pc:04X}  {what:<18} стек: [{"…, " if len(self.stack) > 6 else ""}{top}]'

    def stats(self) -> str:
        h = self.heap
        return ('=== СТАТИСТИКА ===\n'
                f'команд выполнено:     {self.steps}\n'
                f'сборок мусора:        {h.gc_count}\n'
                f'пик / ёмкость кучи:   {h.peak} / {h.capacity}\n'
                f'занято в конце:       {h.used}\n'
                f'объектов создано:     {h.allocated}\n'
                f'объектов освобождено: {h.freed}\n')

    # ── ГЛАВА 3: стек ───────────────────────────────────────────────────
    def push(self, v):
        """Положить значение на стек. Больше STACK_LIMIT — VMError('переполнение стека')."""
        if len(self.stack) >= STACK_LIMIT:
            raise VMError('переполнение стека')

        self.stack.append(v)

    def pop(self):
        """Снять значение. Если стек не выше дна текущего кадра — VMError('стек пуст')."""
        if len(self.stack) <= self.frame.base:
            raise VMError('стек пуст')

        return self.stack.pop()

    def pop_int(self) -> int:
        """Снять ЧИСЛО. Если там ссылка — VMError('ожидалось число')."""
        value = self.pop()

        if isinstance(value, HeapObject):
            raise VMError('ожидалось число')

        return value

    def pop_ref(self) -> HeapObject:
        """Снять ССЫЛКУ на живой объект. Число — 'ожидалась ссылка';
        освобождённый объект — 'обращение к освобождённому объекту'."""
        # TODO 4.3
        raise NotImplementedError('Глава 4: VM.pop_ref')

    # ── ГЛАВА 3: главный цикл ───────────────────────────────────────────
    def step(self):
        """Выполнить одну команду: выборка -> расшифровка -> исполнение.

        1. Взять pc; расшифровать команду decode(self.code, pc).
           Нет такой команды (None) или для неё нет обработчика в self.handlers —
           VMError(f'pc={pc:04X}: неизвестная команда 0x{байт:02X}').
        2. self.steps += 1;  self.pc = адрес следующей команды
           (переходы потом сами перепишут self.pc).
        3. Вызвать обработчик: self.handlers[мнемоника](операнды).
        4. Если обработчик бросил VMError(msg), перебросить
           VMError(f'pc={pc:04X} {мнемоника}: {msg}') — чтобы было видно, где упало.
        """
        pc = self.pc

        # 1. Расшифровываем команду по текущему адресу.
        result = decode(self.code, pc)

        # Если команда неизвестна или её нельзя полностью прочитать.
        if result is None:
            if 0 <= pc < len(self.code):
                byte = self.code[pc]
                byte_text = f'0x{byte:02X}'
            else:
                byte_text = 'неизвестен'

            raise VMError(
                f'pc={pc:04X}: неизвестная команда {byte_text}'
            )

        mnemonic, operands, next_pc = result

        # Проверяем, есть ли обработчик команды.
        if mnemonic not in self.handlers:
            byte = self.code[pc]
            raise VMError(
                f'pc={pc:04X}: неизвестная команда 0x{byte:02X}'
            )

        # 2. Учитываем выполненную команду и переходим к следующей.
        self.steps += 1
        self.pc = next_pc

        # 3. Выполняем команду.
        try:
            self.handlers[mnemonic](operands)

        # 4. Добавляем адрес и название команды к ошибке.
        except VMError as exc:
            raise VMError(
                f'pc={pc:04X} {mnemonic}: {exc}'
            ) from exc


    # ── обработчики команд ──────────────────────────────────────────────
    # Каждый получает список операндов args (может быть пустым).
    # Три уже написаны — по ним видно, как устроены остальные.

    def op_nop(self, args):
        pass

    def op_push(self, args):
        self.push(args[0])

    def op_prints(self, args):
        self.write(self.cart.consts[args[0]])

    def op_halt(self, args):
        self.halted = True

    def op_pop(self, args):
        self.pop()

    def op_dup(self, args):
        value = self.pop()
        self.push(value)
        self.push(value)

    def op_swap(self, args):
        a = self.pop()
        b = self.pop()
        self.push(a)
        self.push(b)

    def op_add(self, args):
        b = self.pop_int()
        a = self.pop_int()
        self.push(wrap32(a + b))

    def op_sub(self, args):
        b = self.pop_int()
        a = self.pop_int()
        self.push(wrap32(a - b))

    def op_mul(self, args):
        b = self.pop_int()
        a = self.pop_int()
        self.push(wrap32(a * b))

    def op_div(self, args):
        b = self.pop_int()
        a = self.pop_int()
        self.push(java_div(a, b))

    def op_mod(self, args):
        b = self.pop_int()
        a = self.pop_int()
        self.push(java_mod(a, b))

    def op_neg(self, args):
        a = self.pop_int()
        self.push(wrap32(-a))

    def op_eq(self, args):
        b = self.pop_int()
        a = self.pop_int()
        self.push(1 if a == b else 0)

    def op_lt(self, args):
        b = self.pop_int()
        a = self.pop_int()
        self.push(1 if a < b else 0)

    def op_gt(self, args):
        b = self.pop_int()
        a = self.pop_int()
        self.push(1 if a > b else 0)

    def op_not(self, args):
        a = self.pop_int()
        self.push(1 if a == 0 else 0)
   
    def op_load(self, args):
        index = args[0]
        if index >= len(self.frame.locals):
            raise VMError('неверный индекс локальной переменной')
        self.push(self.frame.locals[index])

    def op_store(self, args):
        index = args[0]
        if index >= len(self.frame.locals):
            raise VMError('неверный индекс локальной переменной')
        self.frame.locals[index] = self.pop()

    def op_gload(self, args):
        index = args[0]
        if index >= len(self.globals):
            raise VMError('неверный индекс глобальной переменной')
        self.push(self.globals[index])

    def op_gstore(self, args):
        index = args[0]
        if index >= len(self.globals):
            raise VMError('неверный индекс глобальной переменной')
        self.globals[index] = self.pop()

    def op_jmp(self, args):
        self.pc = args[0]

    def op_jz(self, args):
        value = self.pop_int()
        if value == 0:
            self.pc = args[0]

    def op_jnz(self, args):
        value = self.pop_int()
        if value != 0:
            self.pc = args[0]

    def op_print(self, args):
        value = self.pop_int()
        self.write(str(value))

    def op_printc(self, args):
        value = self.pop_int()
        self.write(chr(value))

    def op_assert(self, args):
        value = self.pop_int()
        if value == 0:
            raise VMError(f'ASSERT {args[0]}: тест не пройден')
        
    # TODO 3.5  Напишите остальные обработчики. Имена: 
    #   op_call, op_ret, op_new, op_getf, op_setf, op_len, op_meminfo, op_pix (глава 4)
    #
    # Пример для разгона:
    #
    #   def op_add(self, args):
    #       b = self.pop_int()          # вершина — второй операнд!
    #       a = self.pop_int()
    #       self.push(wrap32(a + b))

    # ── ГЛАВА 6: корни ──────────────────────────────────────────────────
    def roots(self):
        """Все значения, с которых сборщик начинает обход:
        стек операндов, локальные ВСЕХ кадров, глобальные."""
        # TODO 6.1  Удобно сделать генератором:  yield from self.stack  и т. д.
        raise NotImplementedError('Глава 6: VM.roots')


def _short(v):
    return f'obj[{len(v.items)}]' if isinstance(v, HeapObject) else str(v)


# ════════════════════════════════════════════════════════════════════════
#  Готовые инструменты: экран, график, командная строка
# ════════════════════════════════════════════════════════════════════════

PALETTE = [(0x00, 0x00, 0x00), (0x3b, 0x5b, 0xdb), (0xc2, 0x3b, 0x22), (0x8f, 0x3f, 0xa0),
           (0x2f, 0x9e, 0x44), (0x23, 0xa6, 0xc9), (0xe8, 0xc5, 0x47), (0xf2, 0xf2, 0xee)]


def save_png(screen, path, scale=10):
    """Сохранить экран 32×32 в PNG без сторонних библиотек (zlib + struct)."""
    import struct
    import zlib
    w = h = 32 * scale
    raw = bytearray()
    for y in range(h):
        raw.append(0)
        row = screen[y // scale]
        for x in range(w):
            raw.extend(PALETTE[row[x // scale]])

    def chunk(tag, data):
        c = struct.pack('>I', len(data)) + tag + data
        return c + struct.pack('>I', zlib.crc32(tag + data) & 0xFFFFFFFF)
    png = (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0))
           + chunk(b'IDAT', zlib.compress(bytes(raw), 9)) + chunk(b'IEND', b''))
    with open(path, 'wb') as f:
        f.write(png)


def plot_heap(log, capacity, path):
    """График занятости кучи (глава 6). По горизонтали — номер команды, по вертикали — used."""
    # TODO 6.4  matplotlib: точки из log, линия ёмкости (axhline), моменты сборок.
    print('(график кучи ещё не написан — глава 6)')


BENCH_EXPECTED = 'БЕНЧМАРК: КОЛЛАЦ, N = 5000\nЛУЧШЕЕ n = 3711, ДЛИНА = 237\nСУММА ДЛИН = 387940\n'


def calibrate(n=1_500_000):
    """Эталонная нагрузка «как у интерпретатора»: стек, словарь, вызовы методов.
    Нужна, чтобы сравнивать скорость машин на разных ноутбуках (глава 7). Не меняйте её."""
    stack = []
    push, pop = stack.append, stack.pop
    table = {0: lambda a, b: a + b, 1: lambda a, b: a ^ b}
    x = 1
    t0 = time.perf_counter()
    for i in range(n):
        push(i)
        push(x)
        b = pop()
        a = pop()
        x = table[i & 1](a, b) & 0xFFFF
    return n / (time.perf_counter() - t0)


def read_cartridge(path):
    with open(path, 'rb') as f:
        return load(f.read())


def cmd_info(path):
    with open(path, 'rb') as f:
        data = f.read()
    c = load(data)
    kinds = {0: 'основной', 1: 'бенчмарк', 2: 'экзаменационный'}
    print(f'Файл:           {path} ({len(data)} байт)')
    print(f'Версия формата: {c.version[0]}.{c.version[1]}')
    print(f'Владелец:       {c.owner}')
    print(f'Тип:            {c.kind} ({kinds.get(c.kind, "?")})')
    print(f'Ёмкость кучи:   {c.heap} слотов')
    print(f'Глобальных:     {c.nglobals}')
    print(f'Точка входа:    0x{c.entry:04X}')
    print(f'Длина кода:     {len(c.code)} байт')
    print(f'SHA-256:        совпадает')
    print(f'Пул строк ({len(c.consts)}):')
    for i, s in enumerate(c.consts):
        print(f'  {i:>3}: {s!r}')


def cmd_dis(path, out=None):
    text = disassemble(read_cartridge(path))
    if out:
        with open(out, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f'Листинг записан в {out}')
    else:
        print(text, end='')


def cmd_run(path, no_limit=False, heap=None, out_dir='out', trace=False):
    cart = read_cartridge(path)
    vm = VM(cart, heap_capacity=heap, no_limit=no_limit, echo=True, trace=trace)
    t0 = time.perf_counter()
    try:
        vm.run()
    except VMError as e:
        print(f'\nОШИБКА VM: {e}')
    dt = time.perf_counter() - t0
    print()
    print(vm.stats(), end='')
    print(f'время:                {dt:.2f} с')
    os.makedirs(out_dir, exist_ok=True)
    png = os.path.join(out_dir, f'screen_{cart.owner}.png')
    save_png(vm.screen, png)
    print(f'Экран сохранён: {png}')
    if vm.heap.log and not no_limit:
        plot_heap(vm.heap.log, vm.heap.capacity, os.path.join(out_dir, f'heap_{cart.owner}.png'))
    return vm


def cmd_bench(path, profile=False):
    cart = read_cartridge(path)
    vm = VM(cart)
    print('Бенчмарк запущен, подождите…', flush=True)
    t0 = time.perf_counter()
    if profile:
        import cProfile
        import pstats
        prof = cProfile.Profile()
        prof.enable()
    try:
        vm.run()
    except VMError as e:
        print(f'ОШИБКА VM: {e}')
        return
    dt = time.perf_counter() - t0
    if profile:
        prof.disable()
        pstats.Stats(prof).sort_stats('tottime').print_stats(12)
    print(vm.output(), end='')
    ok = vm.output() == BENCH_EXPECTED
    speed = vm.steps / dt
    calib = calibrate()
    index = speed / calib * 1000
    print(f'\nкоманд: {vm.steps:,}   время: {dt:.2f} с   скорость: {speed:,.0f} команд/с'.replace(',', ' '))
    print(f'ответ верный: {"ДА" if ok else "НЕТ — результат не засчитывается"}')
    print(f'КВАНТ-ИНДЕКС: {index:.0f}' if ok else 'КВАНТ-ИНДЕКС: —')
    print(f'(Python {sys.version.split()[0]}; калибровка {calib:,.0f} оп/с)'.replace(',', ' '))


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(prog='kvant.py', description='Эмулятор ЭВМ «Квант-6»')
    sub = p.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('info', help='заголовок и пул строк')
    s.add_argument('file')
    s = sub.add_parser('dis', help='дизассемблер')
    s.add_argument('file')
    s.add_argument('-o', '--out')
    s = sub.add_parser('run', help='запустить картридж')
    s.add_argument('file')
    s.add_argument('--no-limit', action='store_true', help='без ограничения кучи и без сборки')
    s.add_argument('--heap', type=int, help='заменить ёмкость кучи')
    s.add_argument('--out', default='out', help='папка для PNG')
    s.add_argument('--trace', action='store_true', help='печатать каждую команду (в stderr)')
    s = sub.add_parser('bench', help='замер скорости (глава 7)')
    s.add_argument('file')
    s.add_argument('--profile', action='store_true', help='показать, где тратится время')
    a = p.parse_args(argv)
    try:
        if a.cmd == 'info':
            cmd_info(a.file)
        elif a.cmd == 'dis':
            cmd_dis(a.file, a.out)
        elif a.cmd == 'run':
            cmd_run(a.file, a.no_limit, a.heap, a.out, a.trace)
        elif a.cmd == 'bench':
            cmd_bench(a.file, a.profile)
    except LoadError as e:
        print(f'Картридж не загружен: {e}')
        sys.exit(1)
    except FileNotFoundError as e:
        print(f'Нет такого файла: {e.filename}')
        sys.exit(1)
    except NotImplementedError as e:
        print(f'\nЭта часть машины ещё не построена: {e}.\n'
              f'Найдите в kvant.py соответствующий TODO.')
        sys.exit(2)


if __name__ == '__main__':
    main()
