# Cómo entender y defender HostBaseline

## Recorrido del código

1. `Audit.load`: lee un fichero limitado, valida formato, identifica duplicados conflictivos y calcula su hash.
2. `Audit.rules`: define la política y la diferencia entre workstation y router.
3. `Audit.evaluate`: separa cumplimiento, incumplimiento y ausencia de evidencia.
4. `Main`: compara hallazgos por identificador, genera HTML/JSON y devuelve un código de salida útil para automatización.

## Preguntas de entrevista

- ¿Por qué leer directamente sshd_config no basta para conocer la configuración efectiva?
- ¿Qué cambia con Include, Match y el contexto usado en sshd -T?
- ¿Por qué UNKNOWN debe ser diferente de PASS y FAIL?
- ¿Por qué el reenvío IP puede ser correcto en un router y no en un puesto de trabajo?
- ¿Por qué desactivar keyboard-interactive sin conocer el despliegue puede afectar al MFA?
- ¿Qué demuestra un hash SHA-256 de un fichero y qué no demuestra?
- ¿Por qué un cambio de hash no implica necesariamente un cambio de las doce condiciones evaluadas?
- ¿Qué falta para afirmar que un sistema cumple una norma completa de hardening?

## Experimento propio sugerido

En una VM Linux que controles, exporta configuración efectiva con dos contextos SSH distintos y conserva la fecha/contexto de cada captura. Analiza las diferencias sin cambiar la configuración del servicio. Explica qué aspectos el auditor no observa y qué resultados dependen del rol seleccionado.

## Ampliación con contenido técnico

Añade un manifiesto de recolección con hora, rol y contexto SSH, valida su formato y muestra advertencias para muestras antiguas o contextos incompatibles. Mantén clara la diferencia entre metadatos declarados y evidencia autenticada. Añade pruebas antes de anunciar esta función como implementada.
