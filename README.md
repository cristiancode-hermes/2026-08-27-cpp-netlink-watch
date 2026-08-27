# netlink-watch

Monitor de sockets Netlink del kernel Linux en tiempo real (C++23, zero deps).

Lee `/proc/net/netlink` y muestra cada socket netlink del sistema: familia de
protocolo (0 `ROUTE` … 23 `DATAPATH`, con nombre simbólico), port id / PID
propietario (0 = kernel/unbound, y puede superar `2^31-1` porque es un port id,
no un pid), máscara de grupos multicast (con popcount), memoria RX/WMX en
bytes, flag de dump activo, contador de locks, mensajes descartados (`drops`,
típicamente ENOBUFS) e inode del socket. Resuelve el PID a nombre de proceso
vía `/proc/<pid>/comm`. Útil para auditar qué proceso escucha en cada familia
netlink (udev, audit, rutas, generic/genetlink, rdma...), detectar sockets con
drops (mensajes perdidos) y ver quién se suscribe a grupos multicast.

## Features

- **Parse de `/proc/net/netlink`**: formato estándar del kernel, 10 columnas por fila
- **23 familias simbólicas**: `ROUTE`, `AUDIT`, `KOBJECT_UEVENT`, `GENERIC`, `NETFILTER`,
  `INET_DIAG`, `RDMA`, `DATAPATH`… (linux/netlink.h `NETLINK_*`), color por familia
- **Grupos multicast**: máscara hex + popcount; `--groups` filtra solo subscriptores
- **Drops (mensajes perdidos)**: contador en rojo + `--drops` para quedarte con los
  sockets que pierden mensajes (ENOBUFS, requiere `NETLINK_RECV_NO_ENOBUFS`)
- **Port id / PID**: 0 = kernel/unbound; port ids > `2^31-1` se muestran completos
  (no son pids); resolución pid → comm tolerante a procesos muertos
- **Modo watch (`--watch N`)**: refresh periódico con deltas (sockets nuevos/cerrados)
- **Salida JSON (`--json`)**: `summary` + array `sockets` validable con `python -m json.tool`
- **Demo mode (`--demo`)**: host sintético udev + audit + route + apps con 33 sockets
- **Filtros**: `--proto N`, `--groups`, `--drops`, `--pid N`, `--top N`
- **`--file`**: parsea un dump (tolera comentarios `#` y anotaciones)
- **`--no-color`**: paleta ANSI mutable (0 códigos en pipes)
- **Selftest**: 56 checks (parser, familias, grupos, drops, filtros, demo, JSON, `/proc` real)

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o netlink-watch
```

## Usage

```bash
# Snapshot único (host real)
./netlink-watch

# Modo watch (cada 2s) con deltas entre snapshots
./netlink-watch --watch 2

# Solo sockets que pierden mensajes
./netlink-watch --drops

# Solo subscriptores de grupos multicast
./netlink-watch --groups

# Solo la familia GENERIC (genetlink)
./netlink-watch --proto 16

# Sockets de un proceso concreto
./netlink-watch --pid 1082

# JSON
./netlink-watch --json

# Demo (host udev + audit + route + apps sintético)
./netlink-watch --demo

# Parsear un dump con comentarios
./netlink-watch --file sample-netlink.table --no-color

# Sin colores
./netlink-watch --no-color

# Auto-tests
./netlink-watch --selftest
```

## Data Source

`/proc/net/netlink` — tabla de sockets netlink del kernel:

| Campo | Ejemplo | Significado |
|-------|---------|-------------|
| sk | `0000000000000000` | dirección interna del socket kernel |
| Eth | `15` | familia de protocolo (0 `ROUTE` … 23 `DATAPATH`) |
| Pid | `2115` | port id / pid propietario (0 = kernel/unbound) |
| Groups | `00000555` | máscara de grupos multicast (hex), popcount = nº grupos |
| Rmem | `4096` | memoria de cola de recepción (bytes) |
| Wmem | `2048` | memoria de cola de envío (bytes) |
| Dump | `1` | flag de dump en curso |
| Locks | `2` | contador de locks |
| Drops | `17` | mensajes descartados (ENOBUFS) |
| Inode | `9310216` | inode del socket |

Ver `docs/architecture.md` para el flujo interno y las decisiones de diseño.