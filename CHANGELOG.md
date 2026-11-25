# Changelog

Tutte le modifiche rilevanti del progetto sono documentate in questo file.

Il formato segue [Keep a Changelog](https://keepachangelog.com/it-IT/1.1.0/)
e il progetto adotta il [Semantic Versioning](https://semver.org/lang/it/):

- **MAJOR** (`2.0.0`): cambi incompatibili (opzioni CLI rimosse/rinominate, formato JSON/CSV cambiato);
- **MINOR** (`1.1.0`): nuove funzionalità retro-compatibili (nuovi fuzzer, nuove fonti, nuove opzioni);
- **PATCH** (`1.0.1`): correzioni di bug e ritocchi che non cambiano l'interfaccia.

## [Unreleased]

## [1.1.0] - 2026-11-25

### Added
- Pannello **live commands**: durante l'analisi mostra il comando equivalente di ogni operazione
  in background (`dig`, `whois`, `curl`, `chromium --headless`) con contatori per tipo; chiavi oscurate.
  Disattivabile con `--no-activity`.
- Analisi dei **sottodomini** dei lookalike registrati (CT, feed, wildcard DNS, sonda di etichette
  sensibili) e scoperta dei domini che usano il **brand in un sottodominio**
  (es. `brand.it.verifica-conto.com`), con relativi punti e regola di classificazione.
- Colonna **Why** nella tabella dei risultati e livello di pericolosità accanto al punteggio;
  legenda dei livelli nel riepilogo; opzione `--all` per mostrare ogni dominio analizzato.
- Installer interattivo: conferma prima di ogni passaggio importante, verifica reale della creazione
  del venv (con riparazione via `python3-venv`), riuso/ricreazione di `.venv`, aggiunta al `PATH`,
  self-test, opzioni `-y`, `--no-deep`, `--uninstall`. `--setup` chiede conferma per i download pesanti.
- Test per validazione dell'input, feed attività, pacing WHOIS, sottodomini.

### Changed
- L'input deve essere un **dominio**: URL, percorsi, porte, IP, wildcard e TLD inesistenti vengono
  rifiutati prima di iniziare; un host viene ridotto al dominio registrabile.
- **WHOIS senza rate limit**: server ricavato da tabella interna o da IANA via HTTPS (niente più
  query a `whois.iana.org`), sonda di raggiungibilità della porta 43, ritmo adattivo (AIMD) con
  pause e nuovi tentativi invece del blocco del server, budget predefinito 40 query/server.
  Il messaggio "stopped answering (rate limit)" non esiste più; lo stato WHOIS è indicato nella
  riga dei servizi (es. porta 43 bloccata dalla rete).
- Codice riorganizzato in pacchetti: `pipeline/` (uno stadio per modulo) e `ui/`
  (tema, widget, vista live, report); nuovi moduli `activity.py` e `whois.py`.

## [1.0.0] - 2026-11-18

### Added
- Generazione di domini lookalike con 16 tecniche (omoglifi Unicode/IDN, diacritici, whole-script,
  typo da tastiera, bitsquatting, combosquatting IT/EN, cambio TLD) con validazione IDNA2008/UTS-46.
- Scoperta di domini simili da Certificate Transparency (crt.sh) e da feed di phishing
  (OpenPhish, URLhaus, Phishing Army, Phishing.Database).
- Sweep DNS asincrono NS-first con rilevamento dei TLD wildcard, SPF/DMARC del target.
- RDAP tramite bootstrap IANA con fallback WHOIS (porta 43), budget di query e circuit breaker.
- Arricchimento con VirusTotal, AbuseIPDB e urlscan.io (chiavi API facoltative).
- Analisi dei contenuti senza esecuzione di JavaScript: form di login, redirect, offuscamento,
  parking, pagine di blocco dei web filter.
- Confronto visivo di loghi e favicon (pHash/dHash, hash favicon Shodan) e, con `--deep`,
  ORB, screenshot headless e embedding NLP multilingue.
- Indice di rilevanza 0-100 spiegabile e categorie MALICIOUS / SUSPICIOUS / PARKED / COMPETITOR /
  DEFENSIVE / REGISTERED / UNVERIFIED / AVAILABLE.
- Interfaccia da terminale a colori, export opzionale JSON/CSV con `-o`, output JSON su stdout con `--json`.
- Rate limiting per host, back-off, cache a due livelli (RAM + SQLite).
