# netlink-watch — Architecture

## Flujo

```
/proc/net/netlink ──► parse_netlink_file() ──► std::vector<NetlinkSock>
                          │                          │
                          │                          ▼
                          │                  resolve_procs() (port id → comm)
                          │                          │
                          │                ┌─────────┴─────────┐
                          │                ▼                  ▼
                          │          render_snapshot()   render_json()
                          │                │
                          ▼                ▼
                     filtros (proto/groups/drops/pid/top) → watch delta
```

## Decisiones técnicas

- **Monolítico stdlib-only**: un solo TU, `g++ -std=c++23` directo, zero
  dependencias (`<bit>` para popcount, `<charconv>` para parseo).
- **Paleta ANSI mutable**: `--no-color` vacía las strings de color en runtime
  (no `constexpr`) — afecta por igual a selftest, watch y snapshot.
- **Pid es `long long` (port id)**: la columna `Pid` de `/proc/net/netlink` es
  el *netlink port id*, no siempre un pid real — puede superar `2^31-1`
  (ej. `2301669796` visto en host real). Se guarda como `long long` y la
  resolución a `/proc/<pid>/comm` solo se intenta para `1..2^31-1`; fuera de
  rango se muestra `?`. `0` = kernel/unbound (se muestra `-kernel-`).
- **Grupos multicast**: la máscara llega en hex (`00000555`); el número de
  grupos suscritos es `std::popcount(mask)`. `--groups` filtra `mask != 0`.
- **Drops**: mensajes descartados por el socket (ENOBUFS). Solo se contabilizan
  si el socket activó `NETLINK_RECV_NO_ENOBUFS`; un valor alto indica pérdida
  real de mensajes de kernel → resaltado en rojo y filtro `--drops`.
- **Formato kernel**: la primera línea es el header (`sk  Eth ...`); el parser
  la salta detectando el prefijo `sk`/`Sl`, y tolera líneas `#` y anotaciones
  trailing (para dumps con `--file`).
- **Dumps tolerantes**: `--file` salta líneas vacías, comentarios `#` y filas
  malformadas (menos de 10 tokens) sin abortar el parseo.
- **Demo buffer flush**: `demo_load_file()` escribe el fichero demo en un scope
  `{}` que cierra el ofstream ANTES de llamar a `parse_netlink_file()` — sin el
  cierre explícito, el parser leía un fichero vacío (buffer sin flush).

## Riesgos conocidos

- `/proc/net/netlink` refleja solo el network namespace del proceso — en
  contenedores puede mostrar menos sockets que el host (usar `--demo` para
  verificar el render).
- Muchas familias `UNUSED`/`USERSOCK` con pid 0 son sockets kernel internos;
  no son ocupación real de usuariospace.
- El campo `sk` no es un puntero real ni estable entre snapshots — el delta de
  watch se calcula por tupla `(proto, port id, groups, inode)`.