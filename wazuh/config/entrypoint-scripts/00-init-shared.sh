#!/bin/bash
# =============================================================================
# 00-init-shared.sh — fix primo avvio Wazuh Manager su volume vuoto
#
# PERCHE': al primissimo avvio, con il volume 'wazuh_etc' vuoto, la directory
#   /var/ossec/etc/shared/ e il file ar.conf (config Active Response) non esistono
#   ancora. wazuh-analysisd legge ar.conf in fase di parsing e, se manca, esce con
#   ERROR (1103) / CRITICAL (1202) -> il manager non parte affatto.
#
# COSA FA: crea ar.conf vuoto (e il gruppo 'default') se mancano, prima che
#   l'init del container lanci 'wazuh-control start'. Il manager poi rigenera
#   regolarmente il contenuto reale.
#
# COME VIENE ESEGUITO: l'immagine wazuh-manager esegue automaticamente ogni
#   /entrypoint-scripts/*.sh (vedi cont-init.d/2-manager -> function_entrypoint_scripts)
#   PRIMA di avviare i servizi. Questa cartella e' montata via docker-compose.yml.
# =============================================================================

set -e

SHARED_DIR="/var/ossec/etc/shared"
AR_CONF="${SHARED_DIR}/ar.conf"

if [ ! -f "${AR_CONF}" ]; then
    echo "[00-init-shared] ${AR_CONF} mancante: lo creo per evitare il crash di analysisd."
    mkdir -p "${SHARED_DIR}/default"
    : > "${AR_CONF}"
    # Ownership/permessi coerenti con il resto di /var/ossec/etc
    chown -R wazuh:wazuh "${SHARED_DIR}" 2>/dev/null || true
    chmod 660 "${AR_CONF}" 2>/dev/null || true
else
    echo "[00-init-shared] ${AR_CONF} gia' presente: nessuna azione."
fi
