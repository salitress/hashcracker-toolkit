# hashcracker-toolkit

Asistente interactivo en bash (`hashcracker.sh`) para identificar y crackear hashes con `hashcat`, pensado para Kali (rutas de `rockyou`/`seclists` estándar).

## Qué hace

1. **Entrada de hashes** — pega un hash suelto, indica un fichero con uno o varios, o pásalo como argumento (`./hashcracker.sh archivo.hash` o `./hashcracker.sh <hash>`).
2. **Identificación del tipo de hash**, tres caminos:
   - Menú manual: **top 10** más habituales en pentesting (NTLM, NetNTLMv2, MD5, SHA1, SHA2-256/512, sha512crypt/md5crypt, bcrypt, Kerberoast RC4) → opción para ver **otros 25** (AS-REP Roast, Kerberoast AES128/256, NetNTLMv1, LM, MSCache/DCC, WPA-PMKID+EAPOL, 7-Zip, RAR, KeePass, MSSQL, etc.) → opción para introducir el código `-m` exacto.
   - **Detección automática** con `hashcat --identify` (siempre disponible, hashcat ya es dependencia obligatoria) más `hashid` y `name-that-hash` (si están instalados), con reintento por stdin para herramientas que no aceptan el hash como argumento, timeout de seguridad, y recorte de candidatos cuando un hash ambiguo (32/40/64 hex) devuelve decenas de tipos posibles.
   - Vista previa del formato esperado (`hashcat --example-hashes`) para comparar visualmente antes de lanzar nada.
3. **Cracking por wordlists, de más a menos frecuente**:
   - `rockyou.txt` siempre primero y por separado.
   - Wordlists pequeñas (hasta ~1MB: top-común, darkweb, seasons, months, corporate, John, NCSC, fortinet...) fusionadas en **un único pase** de hashcat (dictionary por stdin) para no pagar un reinicio+compilación de kernel por cada fichero diminuto.
   - Wordlists grandes (cientos de miles a millones de contraseñas) probadas una a una, para saber cuál exactamente dio con la contraseña.
   - Pase extra opcional con reglas (`best64.rule`/`best66.rule`, el que exista) sobre `rockyou.txt` si nada más ha funcionado.
   - Corta en cuanto todos los hashes del fichero están crackeados.
4. **Resultado final**: hashes crackeados (usuario:hash:plain), qué wordlists se probaron/omitieron, y sugerencias si algo queda pendiente (reglas más agresivas, wordlists de contexto, mask attack).

## Requisitos

- **hashcat** (obligatorio).
- Opcionales, mejoran la detección automática: `hashid`, `name-that-hash` (`nth`).

```bash
apt install hashcat hashid
pipx install name-that-hash   # o: pip install name-that-hash
```

## Uso

```bash
chmod +x hashcracker.sh

# Modo interactivo (pide el hash/fichero)
./hashcracker.sh

# Pasando un fichero de hashes
./hashcracker.sh jdoe.hash

# Pasando un hash suelto directamente
./hashcracker.sh '$krb5asrep$23$user@DOMAIN.LOCAL:...'
```

## Notas

- Las rutas de wordlists asumen una instalación estándar de Kali (`/usr/share/wordlists/rockyou.txt`, `/usr/share/seclists/...`, `/usr/share/john/password.lst`). Si un fichero no existe, se salta automáticamente y se lista al final como omitido.
- Perfil de carga de GPU configurable en el momento (`-w 3` High / `-w 4` Nightmare, este último más rápido pero puede dejar el equipo poco responsivo bajo carga sostenida).
- `--self-test-disable` se usa para no repetir el auto-test de hashcat en cada uno de los reinicios de la sesión.
- Se filtra el ruido inofensivo de backends sin GPU/NVML disponibles (`clGetPlatformIDs`, `nvmlDeviceGetCount`...); cualquier otro error real de hashcat sí se muestra.
