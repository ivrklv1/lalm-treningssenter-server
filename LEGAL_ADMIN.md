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

Sett `LEGAL_ACK_APP_READY=false` hvis bekreftelseskravet må pauses. Appen får da en tom liste over ventende bekreftelser. Publiserte tekster, versjonshistorikk og kvitteringer blir liggende på disken.

## Lokal integrasjon kontrollert 8. november 2026

Integrasjonsgreina `codex/integrate-legal-20261108` byggjer på server-main
`cd61e58be676a4f37766436133a094dfa61fa351`. Ho tek med dokument-PR #18
og rettingane bevarte i `3ef6dde` på `codex/preserve-legal-fixes-20261108`.

Ved konfliktløysinga er main si eksisterande signeringsmodul og medlemsrute
bevarte. Det finst berre éin instans av signeringstenesta og éi
`GET /api/membership/me`-rute. Tvetydige telefonnummer eller medlems-ID-ar
får ikkje signert økt. Eldre innlogging utan medlems-ID fungerer vidare,
med `memberIdMissing`, men kan ikkje brukast til signerte dokumentkvitteringar.
Gjenteken dokumentbekrefting bevarer opphavleg tidspunkt og kvittering.

Kontroll med Node 24.22.2: 39 servertestar bestod. Den utvida dokumenttesten
følgjer ei simulert kodeinnlogging gjennom medlemsoppslag og bekrefting med
same token. Han kontrollerer medlemsisolasjon, endra datoar, feil versjon,
ugyldige/utløpte/eldre token, gjenteken kvittering og inaktivt/utløpt medlemskap.
Signeringsmodulen er byte-identisk med main. Eksterne integrasjonar er
simulerte, utgåande nettverk er blokkert i testserverane, og data er oppdikta
i mellombelse mapper. Flagg i testprosessane gjeld berre desse prosessane;
ingen innstillingar i køyrande tenester er endra.

Køyr frå integrasjonsmappa med Node 24 og installerte serveravhengigheiter:

```sh
node --check server.js
node --test --test-reporter=tap tests/*.test.js
git -c core.whitespace=cr-at-eol diff --check cd61e58
```

I denne arbeidsstaden vart eksisterande avhengigheiter frå
`../legal-test-server/node_modules` brukte via absolutt `NODE_PATH`.
Integrasjonstestane treng lokal lytting på 127.0.0.1. Fysisk iOS-/Android-test,
visuell adminprøving, stadfesting av produksjonscommit og samordna utrulling
står att. Ingen push, deploy eller aktivering er utført.
