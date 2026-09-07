#!/usr/bin/env bash
#
# hashcracker.sh — Asistente interactivo de identificación y cracking de hashes
# Pensado para Kali (rutas de rockyou/seclists estándar). Requiere: hashcat.
# Opcionales (mejoran la detección automática): hashid, name-that-hash (nth).
#
# Uso: ./hashcracker.sh [HASH | fichero_de_hashes]
#   Sin argumento -> pide el hash/fichero de forma interactiva.
#   Con argumento  -> si es una ruta existente se trata como fichero de hashes,
#                     si no, se trata como un hash literal.

set -uo pipefail

ARG_INPUT="${1:-}"

# ───────────────────────── Colores ─────────────────────────
if [[ -t 1 ]]; then
    C_RESET='\033[0m'; C_BOLD='\033[1m'; C_RED='\033[31m'; C_GREEN='\033[32m'
    C_YELLOW='\033[33m'; C_BLUE='\033[34m'; C_CYAN='\033[36m'
else
    C_RESET=''; C_BOLD=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_CYAN=''
fi

info()  { echo -e "${C_CYAN}[*]${C_RESET} $*"; }
# Recorta listas largas de candidatos (hashes ambiguos de 32/40/64 hex pueden
# dar 30+ tipos "posibles"): muestra como mucho $2 líneas y resume el resto.
limitar_candidatos() {
    local text="$1" max="${2:-8}" total
    [[ -z "$text" ]] && return 0
    total=$(printf '%s\n' "$text" | grep -c .)
    if [[ "$total" -gt "$max" ]]; then
        printf '%s\n' "$text" | head -n "$max"
        echo "   ... (+$((total - max)) candidato(s) más, no mostrados — usa la opción 12/'código exacto' si sabes cuál es)"
    else
        printf '%s\n' "$text"
    fi
}
ok()    { echo -e "${C_GREEN}[+]${C_RESET} $*"; }
warn()  { echo -e "${C_YELLOW}[!]${C_RESET} $*"; }
err()   { echo -e "${C_RED}[-]${C_RESET} $*"; }
title() { echo -e "\n${C_BOLD}${C_BLUE}== $* ==${C_RESET}"; }

WORKDIR="$(mktemp -d /tmp/hashcracker.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

# ───────────────────────── Comprobación de dependencias ─────────────────────────
if ! command -v hashcat &>/dev/null; then
    err "hashcat no está instalado. Instálalo con: apt install hashcat"
    exit 1
fi

HAS_HASHID=0;  command -v hashid &>/dev/null           && HAS_HASHID=1
HAS_NTH=0;     command -v nth &>/dev/null               && HAS_NTH=1

# ───────────────────────── Diccionario de modos hashcat ─────────────────────────
# Top 10 más habituales en pentesting (AD, web, linux, capturas de red)
TOP10_CODES=(1000 5600 0 100 1400 1700 1800 500 3200 13100)
TOP10_NAMES=(
    "NTLM (Windows / Active Directory local)"
    "NetNTLMv2 (capturado con Responder/Inveigh/relay)"
    "MD5"
    "SHA1"
    "SHA2-256"
    "SHA2-512"
    "sha512crypt \$6\$ (/etc/shadow Linux moderno)"
    "md5crypt \$1\$ (/etc/shadow Linux antiguo)"
    "bcrypt \$2*\$ (apps web, /etc/shadow BSD)"
    "Kerberoast — TGS-REP RC4 (etype 23)"
)

# Siguientes 25 más usados (menos frecuentes que el top10, pero habituales)
MORE25_CODES=(18200 19600 19700 5500 3000 1100 2100 7500 22000 2500 1500 7400 122 11600 12500 13600 13400 10900 12000 400 132 1731 8500 9600 6211)
MORE25_NAMES=(
    "AS-REP Roasting (Kerberos, etype 23)"
    "Kerberoast — TGS-REP AES128 (etype 17)"
    "Kerberoast — TGS-REP AES256 (etype 18)"
    "NetNTLMv1"
    "LM (Windows muy antiguo)"
    "MS Cache / DCC (credencial cacheada v1)"
    "MS Cache 2 / DCC2 (credencial cacheada v2)"
    "Kerberos 5, AS-REQ Pre-Auth (etype 23)"
    "WPA-PBKDF2-PMKID+EAPOL (WiFi, hcxpcapngtool)"
    "WPA/WPA2 EAPOL (formato antiguo, prefiere 22000)"
    "descrypt (DES Unix, muy antiguo)"
    "sha256crypt \$5\$ (/etc/shadow Linux)"
    "macOS v10.4 - v10.6"
    "7-Zip"
    "RAR3-hp"
    "WinZip"
    "KeePass 1 / KeePass 2"
    "PBKDF2-HMAC-SHA256 (genérico)"
    "PBKDF2-HMAC-SHA1 (genérico)"
    "phpass (WordPress / phpBB \$P\$ o \$H\$)"
    "MSSQL (2005)"
    "MSSQL (2012+)"
    "RACF (mainframe z/OS)"
    "MS Office 2013 (.docx/.xlsx protegido)"
    "TrueCrypt (PBKDF2-HMAC-RIPEMD160)"
)

# ───────────────────────── Wordlists en orden de prioridad ─────────────────────────
# Se comprueba la existencia de cada una antes de usarla — si tu Kali no tiene
# seclists instalado en /usr/share/seclists, esas simplemente se saltan.
#
# Rockyou va siempre primero y por separado (pedido explícitamente). Las
# demás se dividen en dos tandas:
#   - WORDLISTS_SMALL: listas pequeñas (hasta ~1MB). Se funden en UN solo pase
#     de hashcat (vía stdin) en vez de un reinicio por fichero — cada reinicio
#     de hashcat paga arranque + compilación de kernel (CPU, no GPU), así que
#     con listas tan pequeñas la GPU casi no llega a tener trabajo real antes
#     de que termine esa sesión: por eso se ve poco uso de GPU con muchas
#     wordlists chiquitas encadenadas.
#   - WORDLISTS_LARGE: listas grandes, donde SÍ compensa verlas una a una
#     (más contexto sobre cuál dio con la contraseña, y ya tienen suficiente
#     keyspace para que el arranque de hashcat sea insignificante en proporción).
ROCKYOU="/usr/share/wordlists/rockyou.txt"

WORDLISTS_SMALL=(
    "/usr/share/seclists/Passwords/Common-Credentials/2024-197_most_used_passwords.txt"
    "/usr/share/seclists/Passwords/Common-Credentials/darkweb2017_top-1000.txt"
    "/usr/share/seclists/Passwords/seasons.txt"
    "/usr/share/seclists/Passwords/months.txt"
    "/usr/share/seclists/Passwords/corporate_passwords.txt"
    "/usr/share/john/password.lst"
    "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"
    "/usr/share/seclists/Passwords/Common-Credentials/darkweb2017_top-10000.txt"
    "/usr/share/seclists/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt"
    "/usr/share/seclists/Passwords/Leaked-Databases/fortinet-2021_passwords.txt"
)

WORDLISTS_LARGE=(
    "/usr/share/seclists/Passwords/Common-Credentials/Pwdb_top-100000.txt"
    "/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt"
    "/usr/share/seclists/Passwords/darkc0de.txt"
    "/usr/share/seclists/Passwords/Common-Credentials/Pwdb_top-1000000.txt"
    "/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt"
    "/usr/share/seclists/Passwords/openwall.net-all.txt"
    "/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords.txt"
    "/usr/share/seclists/Passwords/Common-Credentials/Pwdb_top-10000000.txt"
)

# best64.rule y best66.rule son la misma familia de reglas (best66 es la
# evolución de best64 en hashcat moderno); según versión/distro tendrás una u
# otra, así que se usa la primera que exista.
RULES_CANDIDATES=(
    "/usr/share/hashcat/rules/best64.rule"
    "/usr/share/hashcat/rules/best66.rule"
)
RULES_FILE=""
for rf in "${RULES_CANDIDATES[@]}"; do
    if [[ -f "$rf" ]]; then
        RULES_FILE="$rf"
        break
    fi
done

POTFILE="$WORKDIR/hashcat.pot"

# ───────────────────────── Selección del/de los hash(es) ─────────────────────────
title "Entrada de hashes"

HASHFILE="$WORKDIR/hashes.txt"

if [[ -n "$ARG_INPUT" ]]; then
    if [[ -f "$ARG_INPUT" ]]; then
        cp "$ARG_INPUT" "$HASHFILE"
        ok "Hash(es) cargado(s) desde argumento (fichero): $ARG_INPUT"
    else
        printf '%s\n' "$ARG_INPUT" > "$HASHFILE"
        ok "Hash cargado desde argumento"
    fi
else
    echo "1) Pegar un único hash"
    echo "2) Indicar la ruta de un fichero con uno o varios hashes"
    read -rp "Elige [1-2]: " input_choice

    case "$input_choice" in
        1)
            read -rp "Pega el hash: " raw_hash
            printf '%s\n' "$raw_hash" > "$HASHFILE"
            ;;
        2)
            read -rp "Ruta del fichero de hashes: " user_file
            if [[ ! -f "$user_file" ]]; then
                err "No existe el fichero: $user_file"
                exit 1
            fi
            cp "$user_file" "$HASHFILE"
            ;;
        *)
            err "Opción inválida."
            exit 1
            ;;
    esac
fi

TOTAL_HASHES=$(grep -cve '^[[:space:]]*$' "$HASHFILE")
if [[ "$TOTAL_HASHES" -eq 0 ]]; then
    err "El fichero de hashes está vacío."
    exit 1
fi
ok "Cargados $TOTAL_HASHES hash(es) en $HASHFILE"
SAMPLE_HASH=$(grep -m1 -ve '^[[:space:]]*$' "$HASHFILE")

# ───────────────────────── Selección del tipo de hash ─────────────────────────
MODE=""

mostrar_top10() {
    echo
    for i in "${!TOP10_CODES[@]}"; do
        printf "  %2d) [-m %-6s] %s\n" "$((i+1))" "${TOP10_CODES[$i]}" "${TOP10_NAMES[$i]}"
    done
    echo "  11) Ver otros 25 tipos menos comunes"
    echo "  12) Introducir el código exacto de hashcat (-m)"
    echo "   0) Cancelar"
}

mostrar_more25() {
    echo
    for i in "${!MORE25_CODES[@]}"; do
        printf "  %2d) [-m %-6s] %s\n" "$((i+1))" "${MORE25_CODES[$i]}" "${MORE25_NAMES[$i]}"
    done
    echo "   0) Volver a la lista anterior"
}

seleccionar_manual() {
    while true; do
        title "Tipos de hash más comunes en pentesting (top 10)"
        mostrar_top10
        read -rp "Elige una opción: " op
        case "$op" in
            [1-9]|10)
                MODE="${TOP10_CODES[$((op-1))]}"
                return 0
                ;;
            11)
                while true; do
                    title "Otros 25 tipos habituales"
                    mostrar_more25
                    read -rp "Elige una opción: " op2
                    if [[ "$op2" == "0" ]]; then
                        break
                    elif [[ "$op2" =~ ^([1-9]|1[0-9]|2[0-5])$ ]]; then
                        MODE="${MORE25_CODES[$((op2-1))]}"
                        return 0
                    else
                        warn "Opción inválida."
                    fi
                done
                ;;
            12)
                read -rp "Código de modo hashcat (ej. 22000): " MODE
                if [[ ! "$MODE" =~ ^[0-9]+$ ]]; then
                    warn "Debe ser un número."
                    MODE=""
                else
                    return 0
                fi
                ;;
            0)
                exit 0
                ;;
            *)
                warn "Opción inválida."
                ;;
        esac
    done
}

detectar_automatico() {
    title "Detección automática sobre el primer hash"
    echo "Hash de muestra: $SAMPLE_HASH"
    echo

    local result
    # Timeout de seguridad: si una herramienta se queda esperando entrada
    # (algunas son interactivas y no todas soportan argv/stdin igual) no
    # bloquea el script indefinidamente.
    local TO="timeout 10"

    # Cada herramienta se prueba primero pasando el hash como argumento
    # (con </dev/null para que si ignora el argumento y lee stdin no se
    # quede colgada esperando al terminal) y, si no saca nada, por stdin
    # (cat hash | tool) — algunas herramientas solo funcionan de una forma.

    if [[ "$HAS_HASHID" -eq 1 ]]; then
        echo -e "${C_BOLD}--- hashid ---${C_RESET}"
        # Sin -e (extended): -e lista TODOS los tipos que casan por longitud
        # (30+ líneas en un hash de 32 hex). Sin ella, hashid ya prioriza los
        # más probables. Por si acaso, igualmente se recorta con limitar_candidatos.
        result=$($TO hashid -m "$SAMPLE_HASH" </dev/null 2>/dev/null | grep '^\[+\]')
        if [[ -z "$result" ]]; then
            result=$(printf '%s\n' "$SAMPLE_HASH" | $TO hashid -m 2>/dev/null | grep '^\[+\]')
        fi
        if [[ -n "$result" ]]; then
            limitar_candidatos "$result" 8
        else
            warn "hashid no ha detectado ningún tipo para este hash."
        fi
        echo
    else
        warn "hashid no está instalado (apt install hashid)."
    fi

    if [[ "$HAS_NTH" -eq 1 ]]; then
        echo -e "${C_BOLD}--- name-that-hash (nth) ---${C_RESET}"
        result=$($TO nth -t "$SAMPLE_HASH" </dev/null 2>/dev/null | awk '/^Most Likely/{f=1;next} /^$/{f=0} f')
        if [[ -z "$result" ]]; then
            result=$(printf '%s\n' "$SAMPLE_HASH" | $TO nth 2>/dev/null | awk '/^Most Likely/{f=1;next} /^$/{f=0} f')
        fi
        if [[ -n "$result" ]]; then
            limitar_candidatos "$result" 8
        else
            warn "name-that-hash no ha detectado ningún tipo para este hash."
        fi
        echo
    else
        warn "name-that-hash no está instalado (pipx install name-that-hash)."
    fi

    if [[ "$HAS_HASHID" -eq 0 && "$HAS_NTH" -eq 0 ]]; then
        err "Ninguna herramienta de detección está instalada. Elige el modo manualmente."
        return 1
    fi

    echo
    warn "Estas herramientas dan CANDIDATOS, no una certeza absoluta (sobre todo con hashes de 32/40/64 hex, que son ambiguos: MD5/NTLM/MD4 tienen el mismo largo)."
    read -rp "Introduce el código de modo hashcat (-m) que corresponda según lo mostrado arriba: " MODE
    if [[ ! "$MODE" =~ ^[0-9]+$ ]]; then
        warn "Código inválido."
        return 1
    fi
    return 0
}

title "¿Cómo quieres identificar el tipo de hash?"
echo "1) Elegir manualmente de una lista (top 10 + 25 más)"
echo "2) Detección automática (hashid / name-that-hash)"
echo "3) Ya sé el código exacto de hashcat (-m)"
read -rp "Elige [1-3]: " metodo

case "$metodo" in
    1) seleccionar_manual ;;
    2)
        if ! detectar_automatico; then
            warn "Pasando a selección manual..."
            seleccionar_manual
        fi
        ;;
    3)
        read -rp "Código de modo hashcat (-m): " MODE
        if [[ ! "$MODE" =~ ^[0-9]+$ ]]; then
            err "Código inválido."
            exit 1
        fi
        ;;
    *)
        err "Opción inválida."
        exit 1
        ;;
esac

ok "Modo hashcat seleccionado: -m $MODE"

# Vista previa del formato esperado, para poder comparar visualmente con tu hash
if hashcat -m "$MODE" --example-hashes &>/dev/null; then
    echo
    info "Formato de ejemplo para -m $MODE (compáralo con tu hash):"
    hashcat -m "$MODE" --example-hashes 2>/dev/null | grep -E '^Hash-Mode|^Example' | head -n 4
fi

read -rp $'\n¿Continuar con el cracking? [Y/n]: ' seguir
[[ "$seguir" =~ ^[Nn]$ ]] && exit 0

# ───────────────────────── Extra: reglas sobre rockyou ─────────────────────────
# Aplicado por defecto si hay fichero de reglas disponible: cuesta poco tiempo
# extra y añade variantes (mayúsculas, años, leetspeak...) que las wordlists
# planas no cubren.
USE_RULES="n"
if [[ -n "$RULES_FILE" ]]; then
    USE_RULES="y"
    ok "Reglas ($(basename "$RULES_FILE")) se aplicarán sobre rockyou.txt si las wordlists planas no bastan."
else
    warn "No se ha encontrado best64.rule ni best66.rule — se salta el pase con reglas."
fi

# ───────────────────────── Perfil de carga de la GPU ─────────────────────────
# Default: -w 4 (Nightmare, máxima velocidad). En equipos con GPU de sobra
# no suele dejar el sistema colgado, pero si esta vez quieres compartir la
# máquina con otras cosas, puedes bajar a -w 3 (High, más comedido).
WORKLOAD=4
read -rp "¿Bajar a perfil 'High' (-w 3, algo más lento pero deja la máquina usable) en vez de 'Nightmare' (-w 4)? [y/N]: " nm
[[ "$nm" =~ ^[Yy]$ ]] && WORKLOAD=3
ok "Perfil de carga: -w $WORKLOAD"

# ───────────────────────── Bucle de cracking por wordlists ─────────────────────────
contar_crackeados() {
    hashcat -m "$MODE" "$HASHFILE" --show --potfile-path "$POTFILE" 2>/dev/null | grep -cve '^[[:space:]]*$'
}

# Ruido conocido e inofensivo de backends sin GPU/NVML (no son errores reales):
# lo filtramos para no repetirlo en cada wordlist; cualquier otra cosa en
# stderr sí se considera un error real y se muestra.
HC_NOISE_REGEX='clGetPlatformIDs\(\)|nvmlDeviceGetCount\(\)|No NVML adapters found|^[[:space:]]*$'

run_hashcat_filtered() {
    local err_file="$WORKDIR/hc_stderr.tmp"

    # Se lanza en background y se muestra un contador de segundos en la misma
    # línea (sin el spam de estado de hashcat) para que quede claro que sigue
    # vivo durante el arranque/compilación del kernel, aunque el ataque en sí
    # sea silencioso — así no da la sensación de que se ha colgado.
    hashcat "$@" 2>"$err_file" &
    local hc_pid=$!
    local start_ts=$SECONDS
    while kill -0 "$hc_pid" 2>/dev/null; do
        printf '\r    ...trabajando (%ds)' "$((SECONDS - start_ts))"
        sleep 1
    done
    wait "$hc_pid"
    local exit_code=$?
    printf '\r%-30s\r' ""

    local filtered
    filtered=$(grep -vE "$HC_NOISE_REGEX" "$err_file" 2>/dev/null)
    if [[ -n "$filtered" ]]; then
        err "hashcat reportó lo siguiente:"
        echo "$filtered"
    fi
    rm -f "$err_file"
    return "$exit_code"
}

title "Cracking — probando wordlists de más a menos frecuente"

TRIED=()
SKIPPED=()

# Flags de velocidad: -w (perfil de carga, elegido arriba) y
# --self-test-disable (se salta el auto-test que hashcat repite en CADA
# arranque; con ~19 wordlists eso es ~19 auto-tests que aquí no aportan nada
# porque ya sabes que el setup funciona).
SPEED_FLAGS=(-w "$WORKLOAD" --self-test-disable)

cracked_after=$(contar_crackeados)

intentar_wordlist() {
    local wl="$1"
    info "Probando: $wl  ($(du -h "$wl" 2>/dev/null | cut -f1))"
    TRIED+=("$wl")
    # --quiet: silencia el status verboso de hashcat (banner, progreso, etc.).
    # El ruido conocido de backends sin GPU/NVML se filtra; cualquier otro
    # error real (backend, hash malformado...) sí se muestra.
    run_hashcat_filtered -m "$MODE" -a 0 -O "${SPEED_FLAGS[@]}" --quiet "$HASHFILE" "$wl" --potfile-path "$POTFILE"
    local hc_exit=$?
    if [[ "$hc_exit" -ne 0 && "$hc_exit" -ne 1 ]]; then
        err "hashcat devolvió un código de salida inesperado ($hc_exit) probando '$wl' — revisa el error de arriba."
    fi
    cracked_after=$(contar_crackeados)
    ok "Crackeados hasta ahora: $cracked_after / $TOTAL_HASHES"
}

# 1) Rockyou, siempre primero y por separado (pedido explícitamente)
if [[ "$cracked_after" -lt "$TOTAL_HASHES" ]]; then
    if [[ -f "$ROCKYOU" ]]; then
        intentar_wordlist "$ROCKYOU"
    else
        SKIPPED+=("$ROCKYOU")
    fi
fi

# 2) Wordlists pequeñas fusionadas en UN solo pase de hashcat (dictionary por
#    stdin, con "-" como argumento). Evita pagar un reinicio+compilación de
#    kernel (~5-7s de CPU) por cada lista de pocos KB — con tantos reinicios
#    seguidos la GPU apenas llegaba a tener trabajo real antes de que la
#    sesión terminase, de ahí el uso bajo de GPU que se veía.
if [[ "$cracked_after" -lt "$TOTAL_HASHES" ]]; then
    existing_small=()
    for wl in "${WORDLISTS_SMALL[@]}"; do
        if [[ -f "$wl" ]]; then
            existing_small+=("$wl")
        else
            SKIPPED+=("$wl")
        fi
    done

    if [[ "${#existing_small[@]}" -gt 0 ]]; then
        names=""
        for wl in "${existing_small[@]}"; do names+="$(basename "$wl"), "; done
        label="lote pequeño fusionado (${#existing_small[@]} listas: ${names%, })"
        info "Probando: $label"
        TRIED+=("$label")
        cat "${existing_small[@]}" | run_hashcat_filtered -m "$MODE" -a 0 -O "${SPEED_FLAGS[@]}" --quiet "$HASHFILE" - --potfile-path "$POTFILE"
        hc_exit=$?
        if [[ "$hc_exit" -ne 0 && "$hc_exit" -ne 1 ]]; then
            err "hashcat devolvió un código de salida inesperado ($hc_exit) con el lote pequeño — revisa el error de arriba."
        fi
        cracked_after=$(contar_crackeados)
        ok "Crackeados hasta ahora: $cracked_after / $TOTAL_HASHES"
    fi
fi

# 3) Wordlists grandes, una a una — aquí sí compensa: cada una tiene
#    keyspace de sobra para que el arranque de hashcat sea insignificante en
#    proporción, y de paso sabes cuál exactamente dio con la contraseña.
for wl in "${WORDLISTS_LARGE[@]}"; do
    if [[ ! -f "$wl" ]]; then
        SKIPPED+=("$wl")
        continue
    fi
    if [[ "$cracked_after" -ge "$TOTAL_HASHES" ]]; then
        ok "Ya están todos los hashes crackeados. Me salto el resto de wordlists."
        break
    fi
    intentar_wordlist "$wl"
done

# Pase extra con reglas (rockyou + best64/best66) si sigue habiendo hashes sin crackear
if [[ "$USE_RULES" == "y" && "$cracked_after" -lt "$TOTAL_HASHES" && -f "$ROCKYOU" ]]; then
    info "Probando rockyou.txt + reglas $(basename "$RULES_FILE")..."
    run_hashcat_filtered -m "$MODE" -a 0 -O "${SPEED_FLAGS[@]}" --quiet "$HASHFILE" "$ROCKYOU" -r "$RULES_FILE" --potfile-path "$POTFILE"
    hc_exit=$?
    if [[ "$hc_exit" -ne 0 && "$hc_exit" -ne 1 ]]; then
        err "hashcat devolvió un código de salida inesperado ($hc_exit) con rockyou+reglas — revisa el error de arriba."
    fi
    TRIED+=("rockyou.txt + $(basename "$RULES_FILE")")
fi

# ───────────────────────── Resultados ─────────────────────────
title "Resultado final"

FINAL_RESULTS=$(hashcat -m "$MODE" "$HASHFILE" --show --potfile-path "$POTFILE" 2>/dev/null)
FINAL_COUNT=$(echo "$FINAL_RESULTS" | grep -cve '^[[:space:]]*$')

if [[ "$FINAL_COUNT" -gt 0 ]]; then
    ok "Crackeados $FINAL_COUNT / $TOTAL_HASHES:"
    echo "$FINAL_RESULTS"
else
    err "No se ha crackeado ningún hash con las wordlists disponibles."
fi

echo
info "Wordlists probadas (${#TRIED[@]}):"
printf '  - %s\n' "${TRIED[@]}"

if [[ "${#SKIPPED[@]}" -gt 0 ]]; then
    echo
    warn "Wordlists de la lista que no existen en este sistema (${#SKIPPED[@]}, omitidas):"
    printf '  - %s\n' "${SKIPPED[@]}"
fi

if [[ "$FINAL_COUNT" -lt "$TOTAL_HASHES" ]]; then
    echo
    warn "Quedan $((TOTAL_HASHES - FINAL_COUNT)) hash(es) sin crackear. Siguientes pasos posibles:"
    echo "  - Probar con más reglas: rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule"
    echo "  - Wordlists de contexto (nombre de empresa, dominio, temporada+año, etc.)"
    echo "  - Ataque de máscara si sospechas un patrón (ej. ?u?l?l?l?l?d?d?d?d)"
    echo "  - Para AS-REP/Kerberoast: revisa política de contraseñas del dominio (longitud mínima) antes de perder tiempo"
fi

info "Copia local del hash file de esta sesión: $HASHFILE (se borra al salir del script; cópialo si lo quieres conservar)"
