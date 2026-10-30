# Medlemskapsdatoer

Nye ordinære medlemskapsordre lagrer antall bindingsmåneder slik det var da kjøpet ble startet. Når en ordre blir markert betalt, gjør serveren et eget lesende oppslag mot Vipps eCom `GET /ecomm/v2/payments/{orderId}/details`. Bare en vellykket og ikke refundert `SALE` eller `CAPTURE` for riktig ordre og beløp gir betalingsdato. Datoen tolkes i Europe/Oslo. Bindeslutt er betalingsdato pluss antall kalendermåneder fra ordren; den stopper ikke abonnementet.

Serveren svarer raskt på Vipps-meldingen og leser deretter betalingsdetaljene direkte fra Vipps. En callback eller en reservasjon alene aktiverer ikke et medlem. Bare en bekreftet `SALE` eller `CAPTURE` for riktig ordre og beløp gjør det. Ved feil står ordren uavklart, og serveren prøver den igjen omtrent hvert femte minutt i opptil sju dager. En vellykket reservasjon kan belastes med samme idempotensnøkkel som før; medlemskapet aktiveres først etter at Vipps bekrefter belastningen.

Hvis datooppslaget feiler etter at medlemskapet er aktivert, blir datofeltene stående tomme. Serveren prøver datofeltene igjen omtrent hver time. En senere bekreftet medlemskapsordre kan oppdatere datoene, mens en eldre eller gjentatt ordre ikke setter dem tilbake. SMS og Tripletex kjøres først når betalingen er bekreftet hos Vipps.

Endringen fyller ikke inn datoer for eksisterende medlemmer. Historiske datoer krever separat kontroll av medlems-ID, Vipps-ordre, vilkår og backup før import. Appen viser fortsatt eksempeldata på «Mitt medlemskap»; ingen ny offentlig medlemskapsrute inngår her.

En refusjon som kommer etter at et medlemskap allerede er aktivert, behandles fortsatt av den eksisterende medlemsflyten. Automatisk deaktivering ved refusjon inngår ikke i denne endringen og må vurderes separat.

Lokale tester bruker oppdiktede ordrer og oppdiktede Vipps-svar med utgående nettverk blokkert. De dekker bekreftet betaling, falsk «betalt»-melding, reservasjon og et utilgjengelig Vipps-oppslag. I en separat Vipps Merchant Test-tjeneste ble en 1 kr-testordre reservert, fanget og bekreftet. Testmedlemmet fikk betalingsdag 30.10.2026 som medlemsstart og 30.10.2027 som bindeslutt for 12 måneders binding. Testtjenesten hadde egne nøkler og ingen tilgang til SMS, dørstyring, Tripletex eller produksjonens medlemsdata.

Før produksjonsutrulling må refusjon etter aktivering få en uttrykkelig håndteringsregel. Deretter må den første reelle ordren kontrolleres lesende. Eksisterende medlemmers datoer fylles inn separat etter gjennomgang av historiske ordrer og avtalevilkår.
