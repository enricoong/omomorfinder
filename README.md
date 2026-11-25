# OmomorFinder

Strumento da terminale che, dato il **dominio** di un'azienda (es. `example.com`, non un URL),
trova i **domini omomorfi / lookalike** (omoglifi Unicode, IDN, typo, bitsquatting, combosquatting,
cambio TLD, brand usato nei sottodomini), scopre quelli già registrati e assegna a ciascuno un
**indice di pericolosità 0-100** con il **perché**, punto per punto, e una categoria:

| Categoria    | Significato |
|--------------|-------------|
| `MALICIOUS`  | presente in feed di phishing, rilevato da VirusTotal/urlscan, login + brand/logo/contenuto clonato, oppure sottodominio che imita il brand già segnalato |
| `SUSPICIOUS` | molti segnali di rischio (registrazione recente, MX attivo, logo simile, sottodomini "login"...) |
| `PARKED`     | pagina parcheggiata / in vendita / pagina di default: rischio latente |
| `COMPETITOR` | contenuto semanticamente simile ma senza brand né login |
| `DEFENSIVE`  | probabile registrazione difensiva dell'azienda stessa (stesso intestatario, NS, redirect al sito) |
| `REGISTERED` | registrato, pochi segnali |
| `UNVERIFIED` | stato DNS non determinabile (TLD wildcard / timeout) |
| `AVAILABLE`  | libero: candidato per una registrazione difensiva |

Livelli di pericolosità: **80+ CRITICAL**, **60+ HIGH**, **40+ MEDIUM**, **20+ LOW**, sotto 20 INFO.

## Installazione (Kali Linux)

```bash
bash install.sh              # interattivo: chiede conferma prima di ogni passaggio importante
bash install.sh --deep       # include subito i componenti --deep (screenshot, OpenCV, NLP)
bash install.sh -y --no-deep # non interattivo, solo profili fast/standard
bash install.sh --uninstall  # rimuove launcher, .venv, cache e dataset
```

L'installer, in 7 passi numerati, mostra ogni comando prima di eseguirlo e:

1. controlla sistema e Python (≥ 3.11);
2. **verifica davvero** che `python3 -m venv` funzioni (su Kali/Debian manca spesso
   `python3-venv`: in quel caso propone di installarlo con apt);
3. crea `.venv` (o riusa quello esistente, o ricrea quello rotto) e verifica che sia isolato e abbia pip;
4. installa le dipendenze e controlla che si importino;
5. chiede se installare la modalità `--deep` (~1,5 GB: OpenCV, Playwright + Chromium headless, PyTorch CPU);
6. crea il comando `omomorfinder` in `~/.local/bin` e, se serve, lo aggiunge al `PATH` (`~/.zshrc` su Kali);
7. scarica i dataset, crea il modello delle chiavi API e fa un self-test.

In alternativa, una volta pubblicato su un repository git, con [pipx](https://pipx.pypa.io):

```bash
pipx install "git+<URL-del-repository>@v1.1.0"
pipx install "omomorfinder[deep] @ git+<URL-del-repository>"
omomorfinder --setup
```

Chiavi API facoltative in `~/.config/omomorfinder/.env` (oppure `.env` nella cartella corrente):

```ini
VT_API_KEY=...          # VirusTotal (free: 4 req/min)
ABUSEIPDB_API_KEY=...   # AbuseIPDB (free: 1000/giorno)
URLSCAN_API_KEY=...     # urlscan.io (facoltativa)
```

## Uso

```bash
omomorfinder example.com                    # profilo standard
omomorfinder example.it --deep --detail 10  # analisi completa con screenshot
omomorfinder example.com --fast --tlds all  # solo generazione + DNS, tutti i TLD IANA
omomorfinder example.com --all              # mostra la pericolosità di OGNI dominio analizzato
omomorfinder example.com -o risultati       # salva anche JSON + CSV
omomorfinder example.com --no-activity      # nasconde il pannello dei comandi in esecuzione
omomorfinder --help
```

L'input deve essere un dominio: `https://...`, percorsi, porte, indirizzi IP e TLD inesistenti
vengono rifiutati con un messaggio chiaro. Un host (`login.example.com`) viene ridotto al suo
dominio registrabile (`example.com`).

Durante l'analisi il pannello **live commands** mostra, in tempo reale, il comando equivalente
di ciò che il programma sta facendo in background (`dig`, `whois`, `curl` verso RDAP/crt.sh/API,
`chromium --headless`), con i contatori per tipo. Le chiavi API sono sempre oscurate (`***`).

Nell'output finale ogni dominio ha:
- la barra di **pericolosità** con punteggio e livello;
- la colonna **Why** con i motivi principali (es. `+35 listed in OpenPhish`,
  `+20 brand used in subdomain poste.it.verifica-conto.com`);
- nelle schede di dettaglio, la scomposizione completa del punteggio, i sottodomini trovati
  e i dati osservati (IP, NS, MX, registrar, pagina, logo).

## Pipeline

```
dataset ─► profilo target ─► generazione + scoperta (feed, CT, brand nei sottodomini) ─► DNS
        ─► RDAP/WHOIS ∥ web+loghi ∥ CT/urlscan ─► sottodomini ─► AbuseIPDB ─► NLP
        ─► screenshot (deep) ─► pre-score ─► VirusTotal (top-N) ─► score finale
```

Ogni stadio lavora solo sui domini sopravvissuti allo stadio precedente: migliaia di permutazioni
diventano poche decine di analisi costose.

| Tecnica | Dettagli |
|---------|----------|
| Generazione | 16 fuzzer, omoglifi da `confusables.txt` Unicode, validazione IDNA2008/UTS-46, scarto delle etichette mixed-script (non registrabili) |
| Similarità | "scheletro visivo" (confusables + leetspeak + `rn→m`), Damerau-Levenshtein, Jaro-Winkler, fattore TLD |
| Sottodomini | host già visti in CT e nei feed, rilevamento wildcard DNS, sonda DNS di etichette sensibili (`login`, `secure`, `webmail`, `pay`, il brand...), host che imitano il brand (`brand.it.dominio-qualsiasi.com`) |
| DNS | dnspython asincrono, NS-first, rilevamento TLD wildcard, retry dei timeout, SPF/DMARC |
| Registrazione | RDAP via bootstrap IANA (+ RDAP del registrar); WHOIS porta 43 solo per i ccTLD senza RDAP |
| Threat intel | VirusTotal v3, AbuseIPDB v2, crt.sh, urlscan.io, feed OpenPhish / URLhaus / Phishing Army / Phishing.Database |
| Contenuti | HTML scaricato **senza eseguire JavaScript**, limiti di dimensione/tempo; form di login, form verso host esterni, redirect JS, offuscamento, parking, pagine di blocco dei web filter |
| Immagini | pHash DCT + dHash (numpy), hash favicon Shodan (mmh3), SHA-256 copie esatte; ORB OpenCV e screenshot in `--deep` |
| NLP | TF-IDF multilingue, lessico phishing IT/EN; embedding `paraphrase-multilingual-MiniLM-L12-v2` in `--deep` |

## Cortesia verso i servizi (niente rate limit, niente DoS)

- rate limiter per host (intervallo minimo + jitter + concorrenza massima), regole dedicate per
  VirusTotal (derivata dalla quota), crt.sh e RDAP; back-off esponenziale e `Retry-After`;
- **WHOIS senza ban**: il server WHOIS di ogni TLD si ricava da una tabella interna o dal database
  IANA via HTTPS (mai da `whois.iana.org` sulla porta 43); una sonda iniziale rileva se la rete
  blocca la porta 43; il ritmo è **adattivo** (raddoppia l'intervallo e fa una pausa ai primi
  segnali di limitazione, poi riaccelera); al massimo `--whois-limit` query per server, iniziando
  dai domini più rilevanti; risposte in cache per 24 h;
- crt.sh e WHOIS hanno un circuit breaker: un servizio in difficoltà viene lasciato in pace;
- coalescenza delle richieste identiche e cache a due livelli (RAM + SQLite in `~/.cache/omomorfinder`).

## Struttura del codice

| Modulo | Responsabilità |
|--------|----------------|
| `cli.py` | argomenti, validazione del dominio, avvio della scansione, `--setup` |
| `pipeline/` | uno stadio per modulo: `target`, `discovery`, `dns_sweep`, `enrichment`, `subdomains`, `reputation`, `analysis`; `scanner.py` li concatena, `context.py` contiene il contesto condiviso |
| `ui/` | `theme` (colori, banner), `widgets` (barre, badge, "why"), `live` (progresso + comandi live), `render` (report finale) |
| `activity.py` | feed degli eventi "comando equivalente" pubblicati dai client di rete |
| `net.py`, `cache.py` | client HTTP cortese con cache a due livelli |
| `dnsresolve.py`, `registration.py`, `whois.py`, `intel.py` | DNS, RDAP, WHOIS adattivo, API di threat intelligence |
| `generator.py`, `similarity.py` | permutazioni e somiglianza visiva |
| `content.py`, `visual.py`, `nlp.py` | analisi di pagine, immagini e testo |
| `scoring.py`, `models.py` | punteggio spiegabile, categorie, modelli dati |
| `resources.py`, `config.py`, `report.py` | dataset esterni, configurazione, export JSON/CSV |

Ogni modulo, classe e funzione ha una docstring (in inglese) con descrizione, input e output.

## Sviluppo

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"          # aggiungere ,deep per lavorare sulle funzioni --deep
pytest                           # test offline (nessun traffico di rete)
ruff check .                     # lint
```

`.gitignore` esclude ambienti virtuali, build, chiavi API (`.env`) e i risultati delle scansioni,
che possono contenere dati sui target. `.gitattributes` forza i fine riga LF, così `install.sh`
funziona su Kali anche se il repository viene modificato da Windows.

## Versioni e rilascio

Il progetto segue il [Semantic Versioning](https://semver.org/lang/it/) (`MAJOR.MINOR.PATCH`,
dettagli in `CHANGELOG.md`). La versione è definita **solo** in `omomorfinder/__init__.py`
(`__version__`): `pyproject.toml`, `--version`, lo User-Agent e l'export JSON la leggono da lì.

Per pubblicare una nuova versione:

1. aggiornare `__version__` in `omomorfinder/__init__.py`;
2. spostare le voci di `## [Unreleased]` in una nuova sezione `## [X.Y.Z] - AAAA-MM-GG` di `CHANGELOG.md`;
3. verificare: `pytest && ruff check .`;
4. commit e tag annotato:
   ```bash
   git commit -am "Release vX.Y.Z"
   git tag -a vX.Y.Z -m "OmomorFinder X.Y.Z"
   git push --follow-tags
   ```
5. (facoltativo) creare i pacchetti distribuibili con `python -m build` → `dist/*.whl` e `dist/*.tar.gz`.

> I punteggi sono indicatori euristici: verificare manualmente prima di qualsiasi azione
> (takedown, blocchi). Usare lo strumento solo su domini per cui si è autorizzati.
