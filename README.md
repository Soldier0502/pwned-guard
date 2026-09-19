<h1 align="center">pwned-guard</h1>

<p align="center">
Rechaza contraseñas que ya aparecen en filtraciones públicas, sin enviar nunca la contraseña a ningún sitio.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT">
  <img src="https://img.shields.io/badge/node-%3E%3D20-339933" alt="Node >= 20">
  <img src="https://img.shields.io/badge/dependencies-0-blue" alt="Zero dependencies">
  <img src="https://github.com/Soldier0502/pwned-guard/actions/workflows/ci.yml/badge.svg" alt="CI">
</p>

## El problema

La mayoría de las cuentas comprometidas no se pierden por un ataque sofisticado, sino
porque el usuario reutilizó una contraseña que ya está en una filtración anterior. El
atacante no adivina: prueba una lista.

Las reglas clásicas ("una mayúscula, un número, un símbolo") no ayudan contra eso —
`Password1!` las cumple todas y está en cada diccionario. Lo que sirve es comprobar la
contraseña concreta contra el corpus de filtraciones **en el momento del registro o del
cambio**. El problema evidente es que nadie quiere mandar las contraseñas de sus
usuarios a un servicio externo.

`pwned-guard` resuelve justo eso: hace la comprobación sin que la contraseña —ni su
hash completo— salga nunca del proceso.

## Qué hace

- Comprueba una contraseña contra el corpus público de filtraciones usando
  **k-anonymity**: solo se envían 5 caracteres del SHA-1.
- Política configurable: cuántas apariciones se toleran, longitud mínima local y lista
  de bloqueo propia (el nombre de tu producto, tu marca) sin tocar la red.
- `fail-open` o `fail-closed` cuando la API no responde — tú decides si prima la
  disponibilidad o el bloqueo.
- Caché TTL + LRU de prefijos: en un registro con tráfico real la mayoría de las
  consultas no llegan a salir.
- **Cero dependencias.** Probado en Node 20, 22 y 24 (Linux y Windows). Solo usa `fetch`
  y Web Crypto, así que debería funcionar en Deno, Bun y runtimes edge, pero eso **no
  está cubierto por el CI**. Es un paquete solo ESM.
- CLI para revisar una contraseña a mano o dentro de un script.

## Demo

```console
$ printf 'password' | pwned-guard
PWNED    seen 9,659,365 times in known breaches
$ echo $?
1

$ printf 'k9!bosque-tranquilo-42' | pwned-guard
OK       not found in the breach corpus
$ echo $?
0

$ printf 'corto12' | pwned-guard
REJECTED too-short

$ printf 'password' | pwned-guard --json
{
  "allowed": false,
  "pwned": true,
  "count": 9659365,
  "source": "network",
  "reason": "breached"
}
```

> Esta salida se generó contra el servidor de demo del repositorio, para que sea
> reproducible sin red: `node scripts/demo-server.mjs` y añade
> `--endpoint http://127.0.0.1:8787/range` a cada comando. Contra la API pública el
> formato es idéntico y el conteo lo devuelve el servicio en vivo.

## Instalación

```bash
npm install @soldier0502/pwned-guard
```

Sin dependencias transitivas: lo que instalas es este paquete y nada más.

## Uso

```ts
import { createPwnedGuard } from "@soldier0502/pwned-guard";

// Una instancia por proceso: así se comparte la caché entre peticiones.
const guard = createPwnedGuard({ minLength: 10, errorPolicy: "fail-open" });

const result = await guard.check(password);

if (!result.allowed) {
  // result.reason: "too-short" | "blocklisted" | "breached" | "lookup-failed"
  throw new Error("Contraseña rechazada");
}
```

### Opciones

| Opción | Tipo | Por defecto | Qué hace |
|---|---|---|---|
| `maxBreaches` | `number` | `0` | Apariciones toleradas antes de rechazar. `0` rechaza cualquier coincidencia. |
| `errorPolicy` | `"fail-open" \| "fail-closed"` | `"fail-open"` | Qué hacer si la API no responde. |
| `minLength` | `number` | `8` | Longitud mínima, comprobada en local antes de cualquier petición. `0` lo desactiva. |
| `localBlocklist` | `Iterable<string>` | `[]` | Rechazo inmediato, sin red. Normalizado a minúsculas y NFKC. |
| `cacheTtlMs` | `number` | `3600000` | Vida de cada prefijo en caché. |
| `cacheMaxEntries` | `number` | `1024` | Prefijos cacheados como máximo (LRU). |
| `timeoutMs` | `number` | `3000` | Timeout de la petición. |
| `endpoint` | `string` | API pública | Apunta a tu propio mirror si lo autoalojas. |
| `fetchImpl` | `typeof fetch` | global | Inyectable para tests o agentes HTTP propios. |
| `userAgent` | `string` | del paquete | Identifícate: es buena educación con un servicio gratuito. |

### Resultado

| Campo | Qué significa |
|---|---|
| `allowed` | Lo único que necesita la mayoría de los callers. |
| `pwned` / `count` | Si aparece y cuántas veces. `count` es **dato sensible**: no lo registres junto al identificador del usuario. |
| `source` | `network`, `cache`, `local-blocklist`, `policy` o `error`. Útil como métrica. |
| `reason` | `ok`, `too-short`, `blocklisted`, `breached`, `lookup-failed`. Mapéalo a tu mensaje traducido. |

### CLI

```
echo -n "mi contraseña" | pwned-guard [opciones]
```

| Flag | Descripción | Por defecto |
|---|---|---|
| `--max-breaches <n>` | Apariciones toleradas | `0` |
| `--min-length <n>` | Longitud mínima local | `8` |
| `--fail-closed` | Rechazar si la API no responde | desactivado |
| `--timeout <ms>` | Timeout de la petición | `3000` |
| `--endpoint <url>` | Base URL de la API de rangos | pública |
| `--json` | Salida en JSON | desactivado |

Códigos de salida: `0` aceptada, `1` rechazada, `2` error de uso, `3` no se pudo
comprobar (la API no respondió y no pasaste `--fail-closed`). El `3` existe para que un
script no confunda "limpia" con "no lo sé".

### Errores

Cuando la consulta falla, `result.error` es un `RangeLookupError` con un `code` estable:
`timeout`, `network`, `http` (con `status`), `malformed` (la respuesta no era un rango:
un portal cautivo o un WAF que contesta 200 con HTML) o `invalid-input`. Los mensajes
nunca incluyen el prefijo del hash, así que es seguro registrarlos.

La contraseña se lee de **stdin** a propósito: pasarla como argumento la dejaría en el
historial del shell y en la lista de procesos.

## Cómo funciona

```
"password"
   │  SHA-1 local
   ▼
5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
   │
   ├── 5BAA6 ──────────────► GET /range/5BAA6   (lo único que sale del proceso)
   │                              │
   │                              ▼
   │                    ~800 sufijos + conteos
   ▼                              │
1E4C9B93F3F...  ◄── comparación local ──┘
   │
   ▼
{ pwned: true, count: 9659365 }
```

El servidor recibe un prefijo que comparten cientos de contraseñas distintas y devuelve
**todos** los sufijos de ese grupo. Quién está dentro del grupo lo decides tú, en local.
Eso es k-anonymity: el servicio no puede saber cuál de las ~800 preguntaste, ni
siquiera si alguna coincidió.

Tres detalles que importan:

- **Cabecera `Add-Padding`.** Sin ella, el *tamaño* de la respuesta filtra información
  sobre el prefijo consultado. El paquete la envía por defecto y descarta localmente las
  entradas de relleno (`count: 0`).
- **SHA-1 no se usa para almacenar nada.** Es el hash sobre el que está construido el
  corpus; aquí solo existe el tiempo necesario para sacar 5 caracteres. Tú sigues
  guardando las contraseñas con Argon2 o bcrypt.
- **El orden de las comprobaciones.** Longitud → lista local → red. Las dos primeras son
  gratis, así que la mayoría de los rechazos obvios no consumen una petición.

## Integración

En `examples/` (son archivos para copiar a tu proyecto; no se compilan ni se prueban
en el CI de este repo):

- `nextjs-route-handler.ts` — App Router, con mensajes de error en español.
- `express-middleware.ts` — middleware reutilizable para registro y cambio de contraseña.
- `sidecar-server.ts` — servicio HTTP mínimo en loopback, para backends que no son
  JavaScript (.NET, PHP, Python, Go). Tu app llama a `127.0.0.1`; el prefijo lo envía el
  sidecar.

## Privacidad: qué sale y qué no

| Sale del proceso | No sale nunca |
|---|---|
| 5 caracteres hexadecimales del SHA-1 | La contraseña |
| El User-Agent que configures | El hash completo |
| | El identificador del usuario |

El paquete no registra nada por su cuenta. Si añades logs, **nunca** registres la
contraseña ni el par `(usuario, count)`.

## Alcance y uso responsable

Esta es una herramienta **defensiva**: comprueba contraseñas que tus propios usuarios
están eligiendo, en tu propia aplicación, en el momento en que las eligen. No sirve para
auditar contraseñas ajenas y no debe usarse con credenciales que no te pertenecen o que
no tienes autorización escrita para evaluar.

La API pública de rangos es un servicio gratuito: respeta su carga, mantén la caché
activada e identifícate con un `userAgent` propio.

## Limitaciones conocidas

- Solo cubre contraseñas presentes en filtraciones **conocidas y públicas**. Una
  contraseña débil pero inédita (`Carissa2026!`) pasa el filtro: para eso están
  `minLength` y `localBlocklist`.
- La caché es por proceso. Con varias instancias, cada una calienta la suya; si eso te
  importa, apunta `endpoint` a un mirror propio.
- Requiere Web Crypto. En un Node antiguo (< 20) no funciona por diseño.
- `fail-open` es el valor por defecto. Es una decisión de disponibilidad consciente:
  si prefieres bloquear registros antes que aceptar una contraseña sin verificar, pon
  `fail-closed` y monitoriza los `source: "error"`.

## Roadmap

- [ ] Caché compartida opcional (interfaz para Redis/KV).
- [ ] Modo offline con un filtro de Bloom de las N contraseñas más comunes.
- [ ] Comprobación de similitud con datos del usuario (email, nombre de la empresa).
- [ ] Adaptadores publicados para Auth.js y Lucia.

## Desarrollo

```bash
npm install
npm test        # node --test, sin red: todo el HTTP está mockeado
npm run typecheck
npm run build
```

## Licencia

MIT — ver [LICENSE](LICENSE).
