# Cómo entender y defender HostBaseline

## Recorrido del código

1. `Snapshot.parse`: lee un fichero limitado a 4 MiB, exige UTF-8 válido, valida el formato, detecta duplicados contradictorios y calcula el SHA-256 de los bytes.
2. `Rule` y `Audit.rules`: definen la política. Un `Matcher` decide PASS/FAIL (`OneOf` para valores exactos, `Range` para números) y devuelve UNKNOWN si el valor no se puede interpretar. El rol solo cambia el reenvío IP.
3. `Audit.evaluate`: separa cumplimiento, incumplimiento y ausencia de evidencia, y anota el motivo de cada UNKNOWN.
4. `Diff.compare`: compara hallazgos por identificador entre una captura anterior y la actual.
5. `Report`: genera HTML y JSON escapando siempre los valores, que son entrada no confiable.
6. `Main.run`: interpreta la línea de comandos y devuelve un código de salida útil para automatización (`System.exit` solo se llama en `main`, lo que permite probarlo).

## Preguntas de entrevista

- ¿Por qué leer directamente `sshd_config` no basta para conocer la configuración efectiva?
- ¿Qué cambia con `Include`, `Match` y el contexto usado en `sshd -T`?
- ¿Por qué UNKNOWN debe ser distinto de PASS y de FAIL? ¿Por qué `MaxAuthTries abc` es UNKNOWN y no FAIL?
- ¿Por qué el reenvío IP puede ser correcto en un router y no en un puesto de trabajo?
- ¿Por qué `rp_filter = 2` (modo laxo) se acepta y `0` no?
- ¿Por qué desactivar keyboard-interactive sin conocer el despliegue puede afectar al MFA?
- ¿Qué demuestra un hash SHA-256 de un fichero y qué no demuestra?
- ¿Por qué se rechaza un fichero UTF-16 en lugar de intentar leerlo? ¿Qué riesgo tiene "reparar" bytes inválidos en silencio?
- ¿Por qué un cambio de hash no implica un cambio en las comprobaciones evaluadas?
- ¿Qué falta para afirmar que un sistema cumple una norma completa de hardening?

## Experimento propio sugerido

En una VM Linux que controles, exporta la configuración efectiva con dos contextos SSH distintos y conserva la fecha y el contexto de cada captura. Compara con `--baseline` sin cambiar la configuración del servicio. Explica qué aspectos el auditor no observa y qué resultados dependen del rol elegido.

## Ampliaciones con contenido técnico

- Añade una comprobación siguiendo `CONTRIBUTING.md`: ID estable, matcher, justificación, referencia, y pruebas de caso correcto, incorrecto y desconocido antes de anunciarla.
- Añade un manifiesto de recolección con hora, rol y contexto SSH, y avisa de capturas antiguas. Mantén clara la diferencia entre metadatos declarados y evidencia autenticada.
- Mapea cada comprobación a un benchmark real (por ejemplo CIS) **tras verificar los identificadores en la fuente oficial**.
