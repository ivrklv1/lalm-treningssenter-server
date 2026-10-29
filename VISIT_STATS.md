# Besøk per time

Produksjon samler aggregerte tall.

- Bare vellykket døråpning ved hovedinngangen fra `/door/open` eller gammel `/access` telles. Avviste forsøk og adminåpning telles ikke.
- Flere åpninger fra samme medlem eller drop-in-token innen 30 minutter blir ett registrert besøk. Identiteten brukes bare i minnet i opptil 30 minutter.
- `/data/visit-hours.json` lagrer kun dato, klokketimen i Europe/Oslo og antall. Ingen navn, e-post, telefon, medlems-ID eller token skrives til statistikkfilen. Timer eldre enn 12 uker slettes.
- Beregningsmodulen gir først tall etter fire fullførte uker. Da beregner den gjennomsnittlige registrerte døråpninger for hver ukedag og time 05–23 over de siste fire hele ukene. Produksjonsserveren har ingen offentlig API-rute for disse tallene ennå.
- En vellykket dørkommando er ikke bevis for at noen gikk inn eller hvor lenge de var der. Dobbelttellingsvernet i minnet nullstilles ved serveromstart, slik at enkelte besøk kan telles dobbelt ved omstart.
- Gamle `access.log` brukes ikke til bakfylling fordi den har navn/e-post og uensartede logglinjer.

Appen viser fortsatt merkede eksempeldata. Den skal først byttes til ekte aggregater når datagrunnlaget er klart og visningen er testet.
