# Medlemskapsdatoer

Nye ordinære medlemskapsordre lagrer antall bindingsmåneder slik det var da kjøpet ble startet. Når en ordre blir markert betalt, gjør serveren et eget lesende oppslag mot Vipps eCom `GET /ecomm/v2/payments/{orderId}/details`. Bare en vellykket og ikke refundert `SALE` eller `CAPTURE` for riktig ordre og beløp gir betalingsdato. Datoen tolkes i Europe/Oslo. Bindeslutt er betalingsdato pluss antall kalendermåneder fra ordren; den stopper ikke abonnementet.

Oppslaget skjer etter betalingsmottaket og endrer ikke eksisterende betalings-, SMS- eller Tripletex-flyt. Ved feil eller manglende bekreftelse blir datofeltene stående tomme. Serveren prøver uavklarte nye ordre igjen omtrent hver time. En senere bekreftet medlemskapsordre kan oppdatere datoene, mens en eldre eller gjentatt ordre ikke setter dem tilbake.

Endringen fyller ikke inn datoer for eksisterende medlemmer. Historiske datoer krever separat kontroll av medlems-ID, Vipps-ordre, vilkår og backup før import. Appen viser fortsatt eksempeldata på «Mitt medlemskap»; ingen ny offentlig medlemskapsrute inngår her.

Lokale tester bruker oppdiktede ordrer og et oppdiktet Vipps-svar med utgående nettverk blokkert. Testserveren sperrer betaling og kan derfor ikke prøve et ekte Vipps-kjøp.
