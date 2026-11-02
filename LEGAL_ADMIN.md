# Vilkår og personvern i admin

Redigering ligger under **Verktøy → Vilkår og personvern**. Hvert dokument har et privat utkast og én publisert versjon. Første gang er ingen av dokumentene publisert, og appen fortsetter å vise teksten som følger med appen. Testdokumentene fra legal-test kopieres ikke til produksjon.

1. Velg dokument, skriv ny versjon, tittel og innhold.
2. Bruk **Forhåndsvis**, og kontroller teksten og oppsettet.
3. Velg **Lagre utkast**. Dette endrer ikke det appen viser.
4. Når teksten er godkjent, velg **Publiser lagret utkast** og bekreft. Publisering gjør teksten tilgjengelig for apper som henter fra produksjonsserveren, via `/api/legal/terms` eller `/api/legal/privacy`.
5. Kontroller dokumentet i appen etter publisering. Publiserte versjoner kan leses under **Publiserte versjoner**.

Dokumenter og historikk lagres i `legal-documents.json` under serverens `DATA_DIR` (`/data` i produksjon) og tas med i den eksisterende sikkerhetskopien av datamappen. Redigering krever eksisterende admininnlogging. En versjon kan ikke publiseres to ganger, og et utkast basert på en eldre revisjon må lastes på nytt før lagring.

## Ny bekreftelse i appen

I utkastet kan admin velge **Krev ny bekreftelse i appen for denne versjonen** før utkastet lagres. Valget følger den publiserte dokumentversjonen. Medlemsvilkår vises som «Jeg godtar», mens personvern vises som «Jeg har lest». Dette er ikke et personvernsamtykke. Appen viser den publiserte teksten før bekreftelse og holder resten av appen tilbake til bekreftelsen er lagret. Dørendepunktene endres ikke.

Bekreftelser lagres per medlems-ID og versjon, med tidspunkt og historikk, i `legal-acknowledgements.json` på `DATA_DIR`. Appen bruker en signert medlemsøkt fra SMS-innlogging. En gammel lokalt lagret innlogging kan fortsette mens ingen ny bekreftelse kreves; deretter må medlemmet logge inn med SMS én gang. Profiler uten medlems-ID må oppdateres av admin før de kan bekrefte en ny versjon. Signeringsnøkkelen ligger i `legal-member-session.key` på samme disk, eller angis med `LEGAL_MEMBER_SESSION_SECRET` på minst 32 tegn. Begge diskfilene må tas med i backupen.

**Aktiveringsrekkefølge:** Test backend og app sammen, bygg og distribuer appen til iOS og Android, bekreft at eksisterende brukere kan logge inn på nytt og lese/bekrefte dokumentene, og sett først deretter `LEGAL_ACK_APP_READY=true` på serveren. Uten denne innstillingen avvises publisering av dokumenter som krever ny bekreftelse. Publisering uten avhuking virker som før. Appen håndterer også servere som ennå ikke har bekreftelsesendepunktet, men en gammel appversjon viser ikke dette kravet; utrulling må derfor koordineres før avhukingen brukes.
