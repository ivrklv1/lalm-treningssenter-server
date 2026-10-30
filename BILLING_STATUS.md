# Betalingsstatus i admin

Dette er første, **lesende** fase. Administrator klikker «Hent betalingsstatus fra Tripletex». Serveren leser fakturaer og kobler dem til medlems-ID via Vipps-ordrens lagrede Tripletex-ordre-ID. Dette gjelder både nye og eksisterende medlemmer med entydig kobling. Medlemmer uten entydig kobling vises grått som «Må kontrolleres». Oversikten leser fakturaer fra `BILLING_STATUS_FROM` (standard 2024-01-01), og viser tidspunktet for siste kontroll. Eldre fakturaer utenfor perioden inngår ikke.

- **Gul – Fakturert:** Fakturaen har restbeløp, og forfallsdatoen er ikke passert.
- **Rød – Forfalt:** Fakturaen har restbeløp, og forfallsdatoen er passert. En eldre ubetalt faktura vises selv om en nyere faktura er oppgjort.
- **Grønn – Betalt:** Tripletex viser null i restbeløp på en positiv, belastet faktura uten krediteringsflagg. Dette er en operativ status basert på Tripletex, ikke en egen bankavstemming.
- **Grå – Må kontrolleres:** Kobling, faktura eller betalingsopplysninger er ufullstendige eller tvetydige, eller fakturaen er kreditert.

Rødt betyr ikke automatisk sperring. Avtalt regel for en senere fase er sperring først **14 dager etter forfall** og automatisk gjenåpning når full betaling er bekreftet. Den senere fasen må ta hensyn til manuell pause, krediteringer, API-feil og kunder uten sikker ordrekobling. Ingen av disse automatiske adgangsendringene er aktivert her.

Tripletex opplyser at `amountOutstanding = 0` kan bety betalt **eller kreditert**. Derfor blir fakturaer med krediteringsflagg grå og må vurderes manuelt. Ved Tripletex-feil vises ingen gammel status som ny; kontrollen må prøves igjen.

Lokale tester bruker oppdiktede fakturaer og blokkert utgående nettverk. Uthenting mot en ekte Tripletex-konto og visuell kontroll i admin er fortsatt nødvendig før produksjonsutrulling.
