# Betalingsstatus i admin

Dette er første, **lesende** fase. Administrator klikker «Hent betalingsstatus fra Tripletex». Serveren leser fakturaer og kobler dem til medlems-ID via Vipps-ordrens lagrede Tripletex-ordre-ID. Dette gjelder både nye og eksisterende medlemmer med entydig kobling. Medlemmer uten entydig kobling vises grått som «Må kontrolleres». Oversikten leser fakturaer fra `BILLING_STATUS_FROM` (standard 2024-01-01), og viser tidspunktet for siste kontroll. Eldre fakturaer utenfor perioden inngår ikke.

- **Gul – Fakturert:** Fakturaen har restbeløp, og forfallsdatoen er ikke passert.
- **Rød – Forfalt:** Fakturaen har restbeløp, og forfallsdatoen er passert. En eldre ubetalt faktura vises selv om en nyere faktura er oppgjort.
- **Grønn – Betalt:** Tripletex viser null i restbeløp på en positiv, belastet faktura uten krediteringsflagg. Dette er en operativ status basert på Tripletex, ikke en egen bankavstemming.
- **Grå – Må kontrolleres:** Kobling, faktura eller betalingsopplysninger er ufullstendige eller tvetydige, eller fakturaen er kreditert.

Rødt betyr ikke automatisk sperring. Avtalt regel for en senere fase er sperring først **14 dager etter forfall** og automatisk gjenåpning når full betaling er bekreftet. Den senere fasen må ta hensyn til manuell pause, krediteringer, API-feil og kunder uten sikker ordrekobling. Ingen av disse automatiske adgangsendringene er aktivert her.

Tripletex opplyser at `amountOutstanding = 0` kan bety betalt **eller kreditert**. Derfor blir fakturaer med krediteringsflagg grå og må vurderes manuelt. Ved Tripletex-feil vises ingen gammel status som ny; kontrollen må prøves igjen.

Lokale tester bruker oppdiktede fakturaer og blokkert utgående nettverk. Uthenting mot en ekte Tripletex-konto og visuell kontroll i admin er fortsatt nødvendig før produksjonsutrulling.

## Kontrollert utrulling

1. Kontroller at fersk backup av medlemsregisteret finnes.
2. Legg først inn medlemskaps- og adminendringene i PR #12. Deretter kan denne endringen legges på `main`. Produksjonsserveren på Render deployer automatisk fra `main`.
3. Åpne admin og trykk «Hent betalingsstatus fra Tripletex». Noter tidspunktet for kontrollen. Ved API-feil vises ingen status som fersk.
4. Sammenlign minst én faktura i hver aktuell gruppe i Tripletex: fakturert, betalt, forfalt og kreditert. Kontroller fakturanummer, forfallsdato, restbeløp og tilhørende ordre-ID. Del ikke navn eller betalingsdetaljer i en offentlig sak.
5. Tell grå medlemmer uten entydig ordrekobling, og undersøk disse før en senere automatisk sperrefunksjon bygges.

Denne utrullingen endrer ikke `member.active`, abonnement, SMS, betaling eller dørstyring. Ved avvik stoppes innføringen av automatisk sperring; statusvisningen kan fjernes ved å rulle serveren tilbake til forrige versjon.
