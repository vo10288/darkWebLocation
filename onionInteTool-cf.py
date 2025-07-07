#!/usr/bin/env python3

import os
import time
import base64
import requests
import mmh3
import shodan
import re
import argparse
from datetime import datetime
from ipwhois import IPWhois
import folium
from folium.plugins import MarkerCluster

# === CONFIGURA QUI LA TUA API KEY SHODAN ===
SHODAN_API_KEY = "INSERISCI_LA_TUA_API_KEY"

def ensure_log_dir():
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_dir = os.path.join("log-onion", timestamp)
    os.makedirs(log_dir, exist_ok=True)
    return log_dir

def log_output(filename, content, log_dir):
    path = os.path.join(log_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path

def get_favicon_hash(onion_url, log_dir):
    try:
        proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
        response = requests.get(onion_url + "/favicon.ico", proxies=proxies, timeout=15)
        response.raise_for_status()
        favicon = base64.encodebytes(response.content)
        hash_val = mmh3.hash(favicon)
        log_output("favicon_hash.txt", f"Hash: {hash_val}\n", log_dir)
        return hash_val
    except Exception as e:
        log_output("favicon_hash.txt", f"[ERRORE favicon] {e}", log_dir)
        return None

def extract_metadata(onion_url, log_dir):
    try:
        proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(onion_url, proxies=proxies, headers=headers, timeout=20)
        response.raise_for_status()
        html = response.text

        header_data = f"[HEADER]\n{response.headers}\n\n"
        body_snippet = f"[BODY SNIFF]\n{html[:2000]}"
        log_output("site_metadata.txt", header_data + body_snippet, log_dir)

        links = re.findall(r'https?://[^\s\'"]+', html)
        emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", html)
        ids = re.findall(r'UA-\d+-\d+|G-[A-Z0-9]+', html)

        findings = "[LINK ESTERNI]\n" + "\n".join(links) + "\n\n"
        findings += "[EMAIL TROVATE]\n" + "\n".join(emails) + "\n\n"
        findings += "[ID ANALYTICS]\n" + "\n".join(ids) + "\n"
        log_output("content_discovery.txt", findings, log_dir)

    except Exception as e:
        log_output("site_metadata.txt", f"[ERRORE contenuti] {e}", log_dir)

def query_shodan_by_favicon(fav_hash, log_dir):
    ip_info = []
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        results = api.search(f"http.favicon.hash:{fav_hash}")
        output = f"[+] Trovati {results['total']} risultati su Shodan\n\n"
        for r in results['matches']:
            ip = r.get('ip_str')
            port = r.get('port')
            org = r.get('org', 'N/A')
            location = r.get('location', {}).get('country_name', 'N/A')
            city = r.get('location', {}).get('city', 'N/A')
            lat = r.get('location', {}).get('latitude')
            lon = r.get('location', {}).get('longitude')
            hostnames = ", ".join(r.get('hostnames', []))
            output += f"IP: {ip}:{port} - {org} - {location} - {hostnames}\n"
            ip_info.append({
                "ip": ip,
                "port": port,
                "org": org,
                "location": location,
                "city": city,
                "lat": lat,
                "lon": lon,
                "hostnames": hostnames
            })
        log_output("shodan_favicon_results.txt", output, log_dir)
    except Exception as e:
        log_output("shodan_favicon_results.txt", f"[ERRORE Shodan] {e}", log_dir)
    return ip_info

def generate_whois_and_geo(ip_list, log_dir):
    whois_data = ""
    for entry in ip_list:
        ip = entry["ip"]
        try:
            w = IPWhois(ip)
            result = w.lookup_rdap()
            whois_data += f"\n[IP: {ip}]\nASN: {result['asn']}\nOrg: {result['network']['name']}\nCountry: {result['network']['country']}\n"
        except Exception as e:
            whois_data += f"\n[IP: {ip}] WHOIS ERROR: {e}\n"
    log_output("whois_lookup.txt", whois_data, log_dir)

def generate_map(ip_list, log_dir):
    m = folium.Map(location=[20, 0], zoom_start=2)
    marker_cluster = MarkerCluster().add_to(m)
    for entry in ip_list:
        lat = entry.get("lat")
        lon = entry.get("lon")
        if lat and lon:
            folium.Marker(
                location=[lat, lon],
                popup=f"{entry['ip']} - {entry['org']}",
                tooltip=entry['hostnames']
            ).add_to(marker_cluster)
    map_path = os.path.join(log_dir, "shodan_map.html")
    m.save(map_path)
    return map_path

def main(onion_url):
    log_dir = ensure_log_dir()
    print(f"[INFO] Log salvati in: {log_dir}")

    extract_metadata(onion_url, log_dir)

    favicon_hash = get_favicon_hash(onion_url, log_dir)
    if favicon_hash:
        ip_list = query_shodan_by_favicon(favicon_hash, log_dir)
        if ip_list:
            generate_whois_and_geo(ip_list, log_dir)
            generate_map(ip_list, log_dir)
            print("[OK] WHOIS e MAPPA generati")
        else:
            print("[!] Nessun IP trovato in Shodan")
    else:
        print("[!] Nessuna favicon trovata o errore")

    print("[✓] Analisi completata.")

import hashlib
import tarfile

def calculate_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def generate_tar_and_hashes(log_dir):
    # Crea archivio tar.gz
    base_dir = os.path.basename(log_dir)
    tar_path = f"{log_dir}.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(log_dir, arcname=base_dir)

    # Calcola hash dei file nella cartella log
    hash_log = "[HASH FILES INDIVIDUALI]\n"
    for root, dirs, files in os.walk(log_dir):
        for name in files:
            filepath = os.path.join(root, name)
            relpath = os.path.relpath(filepath, log_dir)
            hash_val = calculate_sha256(filepath)
            hash_log += f"{relpath}: {hash_val}\n"

    # Calcola hash dell’archivio tar
    archive_hash = calculate_sha256(tar_path)
    hash_log += f"\n[HASH ARCHIVIO TAR]\n{os.path.basename(tar_path)}: {archive_hash}\n"

    # Salva file log degli hash
    log_output("hashes.txt", hash_log, log_dir)

    print(f"[✓] Archivio creato: {tar_path}")
    print(f"[✓] Hash SHA256 salvati in: {os.path.join(log_dir, 'hashes.txt')}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="🕵️ Onion Intelligence Toolkit")
    parser.add_argument("-i", "--input", required=True, help="Indirizzo .onion da analizzare")
    args = parser.parse_args()
    main(args.input)
