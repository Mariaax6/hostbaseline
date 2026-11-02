# HostBaseline

**Auditor de configuración Linux de solo lectura, en Java 17.** Evalúa capturas explícitas de OpenSSH (`sshd -T`) y de sysctl (`sysctl -a`) frente a una línea base pequeña y sensible al rol del equipo, con 24 comprobaciones. Cada hallazgo conserva el valor observado, el esperado, la severidad, la justificación, la guía de revisión, una referencia a la documentación y la huella SHA-256 de la evidencia. Opcionalmente compara con una captura anterior para ver qué cambió.

Funciona en Windows, Linux y macOS sin librerías externas. Solo lee los ficheros que le das: no se conecta a equipos, no recoge credenciales, no ejecuta comandos ni modifica la configuración.

[English README](README.md) · [Todas las comprobaciones](docs/CHECKS.md) · [Guía de aprendizaje](docs/LEARNING_GUIDE.es.md)

## Uso rápido

```sh
sh build.sh        # Linux/macOS (Windows: .\build.ps1 -JdkHome 'C:\Program Files\Java\jdk-21')
java -jar dist/hostbaseline.jar examples/risky reports/risky --baseline examples/hardened
```

El ejemplo `risky` termina **con código 1 a propósito**: indica que hay comprobaciones fallidas. No es un error del programa. Abre `reports/risky/report.html`.

```text
java -jar hostbaseline.jar <carpeta-captura> <carpeta-informe> [opciones]

  --role workstation|router   Rol de la línea base (por defecto: workstation)
  --baseline <carpeta>        Captura anterior con la que comparar
  --list-checks               Lista las comprobaciones y sale
  --version / -h, --help
```

Cada carpeta de captura contiene `sshd-effective.txt` (salida de `sshd -T`) y `sysctl-effective.txt` (salida de `sysctl -a`). **No uses `sshd_config` en bruto**: `Include` y `Match` solo se resuelven correctamente en el servidor, con su contexto. Los ficheros deben ser **UTF-8**; en PowerShell, `>` genera UTF-16 y la herramienta lo detecta y te lo indica.

## Estados y códigos de salida

- `PASS`: valor explícito que cumple la línea base.
- `FAIL`: valor explícito que no la cumple.
- `UNKNOWN`: falta el fichero o la clave, el valor está vacío, hay duplicados contradictorios o el valor no se puede interpretar. El hallazgo explica el motivo.

Códigos: **0** todo correcto · **1** hay fallos · **3** evidencia desconocida sin fallos · **2** entrada inválida o error de uso.

## Alcance y límites

Es una línea base educativa y con criterio propio, **no** un estándar de hardening ni una certificación (no afirma cumplir CIS, STIG ni similares). No sustituye a un escáner de vulnerabilidades. Queda fuera IPv6, cortafuegos, parches, cifrado de disco, claves de host y permisos de usuarios. Un hash SHA-256 identifica los bytes del fichero, no su autenticidad ni su actualidad.

## Procedencia

El código, las capturas de laboratorio y la documentación se generaron con ayuda de IA. No se auditó ningún servidor real. Entiende y reproduce las comprobaciones antes de presentarlo como trabajo propio; la guía [docs/LEARNING_GUIDE.es.md](docs/LEARNING_GUIDE.es.md) te ayuda a hacerlo.
