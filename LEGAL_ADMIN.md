# Vilkår og personvern i admin

Redigering ligger under **Verktøy → Vilkår og personvern**. Hvert dokument har et privat utkast og én publisert versjon. Første gang er ingen av dokumentene publisert, og appen fortsetter å vise teksten som følger med appen. Testdokumentene fra legal-test kopieres ikke til produksjon.

1. Velg dokument, skriv ny versjon, tittel og innhold.
2. Bruk **Forhåndsvis**, og kontroller teksten og oppsettet.
3. Velg **Lagre utkast**. Dette endrer ikke det appen viser.
4. Når teksten er godkjent, velg **Publiser lagret utkast** og bekreft. Publisering gjør teksten tilgjengelig for apper som henter fra produksjonsserveren, via `/api/legal/terms` eller `/api/legal/privacy`.
5. Kontroller dokumentet i appen etter publisering. Publiserte versjoner kan leses under **Publiserte versjoner**.

Dokumenter og historikk lagres i `legal-documents.json` under serverens `DATA_DIR` (`/data` i produksjon) og tas med i den eksisterende sikkerhetskopien av datamappen. Redigering krever eksisterende admininnlogging. En versjon kan ikke publiseres to ganger, og et utkast basert på en eldre revisjon må lastes på nytt før lagring.

**Ny godkjenning ved innlogging er ikke implementert.** Admin har derfor ingen bryter for dette. Endringer som krever varsling eller nytt samtykke må håndteres som en separat funksjon og prosess.
