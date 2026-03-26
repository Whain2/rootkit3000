# kernmod

Загружаемый модуль ядра Linux для перехвата системных вызовов (`getdents64/getdents`) через ftrace.

## Возможности

* скрытие файлов и каталогов (на уровне `ls`, `find`)
* скрытие процессов (через `/proc`)
* скрытие загруженных модулей ядра
* доверенные процессы (видят скрытые файлы)
* управление через `ioctl` (`/dev/kernmod`)

## Требования

* Linux kernel >= 5.7 (x86_64)
* linux-headers-$(uname -r)
* GCC, Make

## Сборка

```bash
make
```

## Использование

```bash
sudo insmod kernmod.ko

sudo ./client hide-file /path/to/file
sudo ./client unhide-file /path/to/file

sudo ./client hide-pid 1234
sudo ./client unhide-pid 1234

sudo ./client hide-module snd_hda_intel
sudo ./client unhide-module snd_hda_intel

sudo ./client allow-pid 5678
sudo ./client disallow-pid 5678

sudo ./client status

sudo rmmod kernmod
```

⚠️ Перед `rmmod` необходимо сделать `unhide-module kernmod`, если модуль был скрыт.

## Тестирование

```bash
make test
```

Покрывает:

* скрытие файлов
* скрытие процессов
* скрытие модулей
* доверенные PID
* граничные случаи и ошибки

## Структура проекта

```
kernmod.c        — модуль ядра
ftrace.h         — инфраструктура перехвата (ftrace + kprobes)
common.h         — ioctl-интерфейс
client.c         — userspace-утилита
test_viewer.c    — вспомогательная программа для test.sh
test.sh          — автотесты
Makefile         — сборка
```

## Примечания

* Используется ftrace (совместимо с ядрами 5.7+)
* Перехват реализован через `__x64_sys_getdents64` / `__x64_sys_getdents`
* Скрытие работает только на уровне листинга каталогов
  (прямой доступ `open/stat` остаётся)
* Максимум 64 скрытых сущности каждого типа
* Архитектура: x86_64

## Ограничения

* файлы не скрываются от `open/stat`
* процессы можно убить по PID (скрытие только в `/proc`)
* модуль виден через низкоуровневый анализ (ftrace/debugfs)
* требуется адаптация для ARM64/RISC-V

