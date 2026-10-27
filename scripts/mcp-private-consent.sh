#!/usr/bin/env bash
# Owner-only interactive consent; never run from an agent tool transcript.
set -euo pipefail
if [[ ! -t 0 || ! -t 1 ]]; then
  echo 'Ejecuta este paso personalmente en una terminal privada, fuera del chat.' >&2
  exit 2
fi
if (( $# < 3 )); then
  echo 'Uso: mcp-private-consent.sh BIN STATE grant|grant-managed|link [opciones oficiales]' >&2
  exit 2
fi
binary=$1
state=$2
action=$3
shift 3
case "$action" in
  grant|grant-managed)
    if [[ "$action" == grant-managed ]]; then
      policy=${1:?Falta el identificador del catálogo administrado}
      shift
      set -- --managed-catalog "$policy" "$@"
      printf '%s\n' 'Consentimiento a un catálogo administrado: su administrador podrá agregar o retirar hosts, proyectos e hilos sin otra conexión OAuth, dentro del techo de acceso inicial.'
    fi
    printf 'Revisa entorno, proyecto, hilo y acceso antes de emitir el consentimiento:\n'
    printf ' %q' "$binary" --state-dir "$state" mcp grant "$@"
    printf '\nEl código se mostrará sólo aquí. Introdúcelo en el formulario OAuth oficial; no lo pegues en chat.\n'
    read -r -p 'Escribe CONSENTIR para continuar: ' confirmation
    [[ "$confirmation" == CONSENTIR ]] || exit 1
    exec "$binary" --state-dir "$state" mcp grant "$@"
    ;;
  link)
    printf 'Revisa UUID y origen del T3 que autorizarás:\n'
    printf ' %q' "$binary" --state-dir "$state" mcp link-t3 "$@"
    printf '\nCrea un código en Settings → Connections del T3 correspondiente. No lo envíes al agente.\n'
    read -r -s -p 'Código privado de T3: ' pairing
    printf '\n'
    printf '%s\n' "$pairing" | "$binary" --state-dir "$state" mcp link-t3 "$@"
    unset pairing
    ;;
  *) echo 'Acción desconocida: usa grant, grant-managed o link.' >&2; exit 2 ;;
esac
