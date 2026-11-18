# OmomorFinder

Strumento da terminale che, dato il dominio di un'azienda, trova i **domini omomorfi / lookalike**
(omoglifi Unicode, IDN, typo, bitsquatting, combosquatting, cambio TLD), scopre quelli già registrati
e assegna a ciascuno un **indice di rilevanza 0-100 spiegabile** e una categoria:

| Categoria    | Significato |
|--------------|-------------|
| `MALICIOUS`  | presente in feed di phishing, rilevato da VirusTotal/urlscan, oppure login + brand/logo/contenuto clonato |
| `SUSPICIOUS` | molti segnali di rischio (registrazione recente, MX attivo, logo simile, ...) |
| `PARKED`     | pagina parcheggiata / in vendita / pagina di default: rischio latente |
| `COMPETITOR` | contenuto semanticamente simile ma senza brand né login |
| `DEFENSIVE`  | probabile registrazione difensiva dell'azienda stessa (stesso intestatario, NS, redirect al sito) |
| `REGISTERED` | registrato, pochi segnali |
| `UNVERIFIED` | stato DNS non determinabile (TLD wildcard / timeout) |
| `AVAILABLE`  | libero: candidato per una registrazione difensiva |

## Installazione (Kali Linux)

```bash
bash install.sh            # profili fast e standard
bash install.sh --deep     # + screenshot (Chromium), ORB/OpenCV, embedding NLP
```

L'installer crea un virtualenv (`.venv`, necessario su Kali per PEP 668), installa le dipendenze,
crea il comando `omomorfinder` in `~/.local/bin` e scarica tutti i dataset esterni.

Chiavi API facoltative in `~/.config/omomorfinder/.env` (oppure `.env` nella cartella corrente):

```ini
VT_API_KEY=...          # VirusTotal (free: 4 req/min)
ABUSEIPDB_API_KEY=...   # AbuseIPDB (free: 1000/giorno)
URLSCAN_API_KEY=...     # urlscan.io (facoltativa)
```

## Uso

```bash
omomorfinder example.com                        # profilo standard
omomorfinder https://www.example.it --deep      # analisi completa con screenshot
omomorfinder example.com --fast --tlds all      # solo generazione + DNS, tutti i TLD IANA
omomorfinder example.com --top 50 --detail 10      # più righe e più schede di dettaglio
omomorfinder example.com -o risultati              # salva anche JSON + CSV
omomorfinder example.com --proxy socks5://127.0.0.1:9050 --resolvers 1.1.1.1,9.9.9.9
omomorfinder --setup                            # pre-scarica dataset, Chromium, modello NLP
omomorfinder --help
```

## Pipeline

```
dataset ─► profilo target ─► generazione + scoperta (CT, feed) ─► DNS (NS→A/AAAA/MX)
        ─► RDAP/WHOIS ∥ web+loghi ∥ CT/urlscan ─► AbuseIPDB ─► NLP ─► screenshot (deep)
        ─► pre-score ─► VirusTotal (top-N, rispettando la quota) ─► score finale + report
```

Ogni stadio lavora solo sui domini sopravvissuti allo stadio precedente: migliaia di permutazioni
diventano poche decine di analisi costose.

| Tecnica | Dettagli |
|---------|----------|
| Generazione | 16 fuzzer, omoglifi da `confusables.txt` Unicode, validazione IDNA2008/UTS-46, scarto delle etichette mixed-script (non registrabili) |
| Similarità | "scheletro visivo" (confusables + leetspeak + `rn→m`), Damerau-Levenshtein, Jaro-Winkler, fattore TLD |
| DNS | dnspython asincrono, NS-first, rilevamento TLD wildcard, retry dei timeout, SPF/DMARC |
| Registrazione | RDAP via bootstrap IANA (+ RDAP del registrar), fallback WHOIS porta 43 con referral IANA e parser a sezioni (formato `.it`) |
| Threat intel | VirusTotal v3, AbuseIPDB v2, crt.sh (Certificate Transparency), urlscan.io, feed OpenPhish / URLhaus / Phishing Army / Phishing.Database |
| Contenuti | HTML scaricato **senza eseguire JavaScript**, limiti di dimensione/tempo; form di login, form verso host esterni, redirect JS, offuscamento, parking |
| Immagini | pHash DCT + dHash (numpy), hash favicon Shodan (mmh3), SHA-256 copie esatte; ORB OpenCV e screenshot Playwright in `--deep` |
| NLP | TF-IDF multilingue senza dipendenze, lessico phishing IT/EN; embedding `paraphrase-multilingual-MiniLM-L12-v2` in `--deep` |

## Cortesia verso i servizi (anti-DoS)

- rate limiter per host (intervallo minimo + jitter casuale + concorrenza massima), regole dedicate
  per VirusTotal (derivata dalla quota), crt.sh, RDAP e WHOIS;
- back-off esponenziale e rispetto di `Retry-After`; disattivazione automatica a quota esaurita;
- coalescenza delle richieste identiche concorrenti;
- cache a due livelli (LRU in RAM + SQLite in `~/.cache/omomorfinder`) con TTL per fonte:
  una seconda scansione dello stesso target non genera quasi traffico.

## Output

Solo terminale: tabella a colori, schede di dettaglio con la scomposizione del punteggio e
raccomandazioni operative. Con `-o DIR` i risultati vengono salvati anche in `*.json` (completo)
e `*.csv`; con `--json` il JSON viene stampato su stdout (per pipe/script).

> I punteggi sono indicatori euristici: verificare manualmente prima di qualsiasi azione
> (takedown, blocchi). Usare lo strumento solo su domini per cui si è autorizzati.
