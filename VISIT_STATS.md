# Besøk per time – klargjort, ikke aktivert i produksjon

- Kilde: Bare vellykket døråpning ved hovedinngangen (`/door/open` og gammel `/access`). Avviste forsøk, adminåpning og legal-test-døråpning telles ikke.
- Dobbelttelling: Flere åpninger fra samme medlem eller drop-in-token innen 30 minutter blir ett registrert besøk. Identiteten beholdes bare i minnet i opptil 30 minutter.
- Lagring: `/data/visit-hours.json` inneholder dato, klokketimen i Europe/Oslo og antall. Ingen navn, telefonnumre, e-postadresser, medlems-ID-er eller token lagres i denne filen. Timer eldre enn 12 uker fjernes.
- Visning: `GET /api/visit-pattern` gir først tall etter åtte fullførte uker. Den returnerer gjennomsnittet for hver ukedag og time 05–23 over de siste åtte hele ukene. Før det returnerer den `available: false`.
- Betydning: Dette måler registrerte vellykkede døråpninger, ikke faktisk antall personer som gikk inn eller hvor mange som oppholdt seg i senteret samtidig. Dobbelttellingsvernet i minnet nullstilles ved serveromstart, så en åpning rett etter omstart kan gi et ekstra besøk.
- Historikk: Eksisterende `access.log` har navn eller e-post og varierende formater, så den brukes ikke til å beregne eller fylle inn gamle besøkstall.

Legal-test kan lese en tom statistikkrespons, men døråpning er fortsatt sperret. Appen beholder merkede eksempeldata inntil produksjon har samlet nok historikk og visningen er testet. Ingen produksjonsutrulling er utført for denne endringen.
