#!/bin/bash

# Script de reconnaissance de sous-domaines
# Interroge crt.sh, vérifie DNS, teste port 443 et valide les certificats SSL

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variables globales
ENABLE_IPV6=false

# Vérifier les dépendances
check_dependencies() {
    local deps=("curl" "jq" "timeout" "openssl")
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            echo -e "${RED}Erreur: $cmd n'est pas installé${NC}"
            exit 1
        fi
    done
}

# Fonction pour afficher l'usage
usage() {
    echo "Usage: $0 <domain> [options]"
    echo ""
    echo "Options:"
    echo "  --ipv6    Inclure les adresses IPv6 dans les résultats"
    echo ""
    echo "Exemples:"
    echo "  $0 example.com"
    echo "  $0 example.com --ipv6"
    exit 1
}

# Parser les arguments
DOMAIN=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --ipv6)
            ENABLE_IPV6=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            if [ -z "$DOMAIN" ]; then
                DOMAIN="$1"
            else
                echo "Erreur: Argument inconnu '$1'"
                usage
            fi
            shift
            ;;
    esac
done

if [ -z "$DOMAIN" ]; then
    usage
fi

# Fonction pour récupérer les sous-domaines depuis crt.sh
get_crtsh_subdomains() {
    local domain="$1"
    echo -e "${CYAN}### Fetching subdomains for $domain on crt.sh${NC}"
    
    local url="https://crt.sh/?q=%25.$domain&output=json"
    local response
    
    response=$(curl -s --max-time 20  -A "Mozilla/5.0" "$url")
    
    if [ -z "$response" ]; then
        echo -e "${YELLOW}### No results returned from crt.sh${NC}"
        return 1
    fi
    
    # Vérifier si la réponse est du JSON valide
    if ! echo "$response" | jq empty 2>/dev/null; then
        echo -e "${RED}### Error: Invalid JSON response from crt.sh${NC}"
        echo -e "${YELLOW}### Response preview: ${response:0:200}${NC}"
        return 1
    fi
    
    if [ "$response" == "[]" ]; then
        echo -e "${YELLOW}### No certificates found for $domain${NC}"
        return 1
    fi
    
    # Parser le JSON et extraire les sous-domaines uniques
    echo "$response" | jq -r '.[].name_value' 2>/dev/null | \
        tr '\n' ' ' | tr ' ' '\n' | \
        grep -v "^\*\." | \
        grep -v "^$" | \
        sort -u > /tmp/subdomains_raw.txt
    
    local count=$(wc -l < /tmp/subdomains_raw.txt)
    
    if [ "$count" -eq 0 ]; then
        echo -e "${YELLOW}### No valid subdomains found after filtering${NC}"
        return 1
    fi
    
    echo -e "${GREEN}### $count unique subdomains found${NC}"
}

# Fonction pour vérifier les enregistrements DNS via Google DNS
get_google_dns_record() {
    local hostname="$1"
    local ips=""
    
    # Requête A (IPv4)
    local respA=$(curl -s --max-time 10 "https://dns.google/resolve?name=$hostname&type=A")
    if echo "$respA" | jq -e '.Answer' &> /dev/null; then
        local ipv4=$(echo "$respA" | jq -r '.Answer[]? | select(.type==1) | .data' 2>/dev/null)
        ips="$ipv4"
    fi
    
    # Requête AAAA (IPv6) - uniquement si le flag est activé
    if [ "$ENABLE_IPV6" = true ]; then
        local respAAAA=$(curl -s --max-time 10 "https://dns.google/resolve?name=$hostname&type=AAAA")
        if echo "$respAAAA" | jq -e '.Answer' &> /dev/null; then
            local ipv6=$(echo "$respAAAA" | jq -r '.Answer[]? | select(.type==28) | .data' 2>/dev/null)
            if [ -n "$ipv6" ]; then
                if [ -n "$ips" ]; then
                    ips="$ips, $ipv6"
                else
                    ips="$ipv6"
                fi
            fi
        fi
    fi
    
    if [ -n "$ips" ]; then
        echo "true|$ips"
    else
        echo "false|"
    fi
}

# Fonction pour tester le port 443
test_port_443() {
    local hostname="$1"
    
    # Utiliser timeout avec nc (netcat) ou bash built-in
    if command -v nc &> /dev/null; then
        timeout 5 nc -zv "$hostname" 443 &> /dev/null
        return $?
    else
        # Alternative avec bash uniquement
        timeout 5 bash -c "exec 3<>/dev/tcp/$hostname/443" &> /dev/null
        return $?
    fi
}

# Fonction pour vérifier le certificat SSL
test_server_certificate() {
    local hostname="$1"
    
    # Récupérer les informations du certificat
    local cert_info=$(echo | timeout 5 openssl s_client -servername "$hostname" -connect "$hostname:443" 2>/dev/null | \
        openssl x509 -noout -dates -subject 2>/dev/null)
    
    if [ -z "$cert_info" ]; then
        echo "false|false|||"
        return
    fi
    
    local not_before=$(echo "$cert_info" | grep "notBefore" | cut -d= -f2-)
    local not_after=$(echo "$cert_info" | grep "notAfter" | cut -d= -f2-)
    local subject=$(echo "$cert_info" | grep "subject" | cut -d= -f2-)
    
    # Extraire uniquement le CN (Common Name) du sujet
    local cert_hostname=""
    if echo "$subject" | grep -q "CN"; then
        # Extraire le CN du format "CN=example.com" ou "CN = example.com, O=Org, C=US"
        cert_hostname=$(echo "$subject" | grep -oP 'CN\s*=\s*\K[^,]+' | head -1 | xargs)
    fi
    
    # Si pas de CN trouvé, garder le sujet complet
    if [ -z "$cert_hostname" ]; then
        cert_hostname="$subject"
    fi
    
    # Vérifier si c'est un certificat wildcard
    local is_wildcard="false"
    if echo "$cert_hostname" | grep -q "^\*\."; then
        is_wildcard="true"
    fi
    
    # Vérifier si le certificat est valide maintenant
    local current_date=$(date +%s)
    local not_before_ts=$(date -d "$not_before" +%s 2>/dev/null || echo 0)
    local not_after_ts=$(date -d "$not_after" +%s 2>/dev/null || echo 0)
    
    local is_valid="false"
    if [ "$not_before_ts" -le "$current_date" ] && [ "$not_after_ts" -ge "$current_date" ]; then
        is_valid="true"
    fi
    
    echo "true|$is_valid|$not_after|$is_wildcard|$cert_hostname"
}

# Fonction principale de scan
scan_subdomains() {
    echo -e "${CYAN}### Checking DNS records with dns.google API, testing tcp/443 con...${NC}"
    
    # Compter le nombre total de sous-domaines
    local total=$(wc -l < /tmp/subdomains_raw.txt)
    local current=0
    
    # Créer le fichier de résultats
    echo "Subdomain|HasDNSRecord|IP|Port443Open|CertValidNow|IsWildcardCert|CertSubject|NotAfterTLS" > /tmp/results.txt
    
    while IFS= read -r subdomain; do
        [ -z "$subdomain" ] && continue
        
        ((current++))
        echo -e "${CYAN}## Testing DNS entry and TCP443 port on: [$current/$total] $subdomain${NC}"
        
        # Vérifier DNS
        local dns_result=$(get_google_dns_record "$subdomain")
        local has_dns=$(echo "$dns_result" | cut -d'|' -f1)
        local ip=$(echo "$dns_result" | cut -d'|' -f2)
        
        # Tester port 443
        local port443="false"
        if [ "$has_dns" == "true" ]; then
            if test_port_443 "$subdomain"; then
                port443="true"
            fi
        fi
        
        # Vérifier certificat si port ouvert
        local cert_valid="false"
        local is_wildcard="false"
        local subject=""
        local not_after=""
        
        if [ "$port443" == "true" ]; then
            local cert_result=$(test_server_certificate "$subdomain")
            local https_open=$(echo "$cert_result" | cut -d'|' -f1)
            cert_valid=$(echo "$cert_result" | cut -d'|' -f2)
            not_after=$(echo "$cert_result" | cut -d'|' -f3)
            is_wildcard=$(echo "$cert_result" | cut -d'|' -f4)
            subject=$(echo "$cert_result" | cut -d'|' -f5)
        fi
        
        # Enregistrer les résultats
        echo "$subdomain|$has_dns|$ip|$port443|$cert_valid|$is_wildcard|$subject|$not_after" >> /tmp/results.txt
        
    done < /tmp/subdomains_raw.txt
}

# Fonction pour afficher les résultats
display_results() {
    echo ""
    echo -e "${GREEN}### All Results:${NC}"
    column -t -s'|' /tmp/results.txt
    
    echo ""
    echo -e "${GREEN}### Matching Active DNS records entry and open 443 port, seek for deprecated cert with open TCP con...${NC}"
    
    # Filtrer les entrées valides (DNS + Port443 + CertValid)
    grep -v "^Subdomain" /tmp/results.txt | awk -F'|' '$2=="true" && $4=="true" && $5=="true"' > /tmp/valid_https.txt
    
    if [ -s /tmp/valid_https.txt ]; then
        (echo "Subdomain|HasDNSRecord|IP|Port443Open|CertValidNow|IsWildcardCert|CertSubject|NotAfterTLS"; cat /tmp/valid_https.txt) | column -t -s'|'
    else
        echo "No valid HTTPS entries found"
    fi
}

# Nettoyage des fichiers temporaires
cleanup() {
    rm -f /tmp/subdomains_raw.txt /tmp/results.txt /tmp/valid_https.txt
}

# Programme principal
main() {
    check_dependencies
    
    get_crtsh_subdomains "$DOMAIN"
    
    if [ ! -f /tmp/subdomains_raw.txt ] || [ ! -s /tmp/subdomains_raw.txt ]; then
        echo -e "${RED}No subdomains to scan${NC}"
        exit 1
    fi
    
    scan_subdomains
    display_results
    cleanup
}

# Gérer l'interruption proprement
trap cleanup EXIT

main
none
