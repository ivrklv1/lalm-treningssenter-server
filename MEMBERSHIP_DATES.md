# Medlemskapsdatoer

Nye ordinære medlemskapsordre lagrer antall bindingsmåneder slik det var da kjøpet ble startet. Når en ordre blir markert betalt, gjør serveren et eget lesende oppslag mot Vipps eCom `GET /ecomm/v2/payments/{orderId}/details`. Bare en vellykket og ikke refundert `SALE` eller `CAPTURE` for riktig ordre og beløp gir betalingsdato. Datoen tolkes i Europe/Oslo. Bindeslutt er betalingsdato pluss antall kalendermåneder fra ordren; den stopper ikke abonnementet.

Serveren svarer raskt på Vipps-meldingen og leser deretter betalingsdetaljene direkte fra Vipps. En callback eller en reservasjon alene aktiverer ikke et medlem. Bare en bekreftet `SALE` eller `CAPTURE` for riktig ordre og beløp gjør det. Ved feil står ordren uavklart, og serveren prøver den igjen omtrent hvert femte minutt i opptil sju dager. En vellykket reservasjon kan belastes med samme idempotensnøkkel som før; medlemskapet aktiveres først etter at Vipps bekrefter belastningen.

Hvis datooppslaget feiler etter at medlemskapet er aktivert, blir datofeltene stående tomme. Serveren prøver datofeltene igjen omtrent hver time. En senere bekreftet medlemskapsordre kan oppdatere datoene, mens en eldre eller gjentatt ordre ikke setter dem tilbake. SMS og Tripletex kjøres først når betalingen er bekreftet hos Vipps.

Endringen fyller ikke inn datoer for eksisterende medlemmer. Historiske datoer krever separat kontroll av medlems-ID, Vipps-ordre, vilkår og backup før import. Appen viser fortsatt eksempeldata på «Mitt medlemskap»; ingen ny offentlig medlemskapsrute inngår her.

Lokale tester bruker oppdiktede ordrer og oppdiktede Vipps-svar med utgående nettverk blokkert. De dekker bekreftet betaling, falsk «betalt»-melding, reservasjon og et utilgjengelig Vipps-oppslag. Testserveren sperrer betaling og kan derfor ikke prøve et ekte Vipps-kjøp. Utkastet må gjennomgås før produksjonsutrulling; deretter må den første reelle ordren kontrolleres uten å starte en testbetaling.
