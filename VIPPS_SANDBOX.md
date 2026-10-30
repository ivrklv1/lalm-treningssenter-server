# Isolert Vipps-test for medlemsdatoer

Denne grenen er bare for den **separate** Render-webtjenesten [lalm-vipps-sandbox](https://dashboard.render.com/web/srv-dbi4mcijnfac73cqg21g). `server.js` nekter å starte uten testmodus. Den skal ikke kobles til produksjon, den eldre SMS-testtjenesten eller legal-test-tjenesten.

## Før opprettelse

- Kildegren: `codex/vipps-sandbox-isolation` (bygger på utkastet i PR #12).
- Startkommando: `node server.js`. Byggkommando: `npm ci`.
- Egen Render-webtjeneste med egen URL, uten delt disk eller miljøgruppe.
- Ingen eksisterende `members.json` eller `orders.json` kopieres inn.
- Tjenesten er opprettet på gratisplanen, i Frankfurt, uten automatisk utrulling.

## Miljøvariabler på den nye tjenesten

| Navn | Verdi |
| --- | --- |
| `VIPPS_SANDBOX_ONLY` | `1` |
| `VIPPS_ENV` | `test` |
| `VIPPS_MSN` | `411837` |
| `DATA_DIR` | `/tmp/lalm-vipps-sandbox` |
| `SERVER_URL` | Den nye tjenestens HTTPS-URL, uten avsluttende `/` |
| `VIPPS_CALLBACK_URL` | `SERVER_URL` + `/vipps/callback` (Vipps legger selv til `/v2/payments/{orderId}`) |
| `VIPPS_CLIENT_ID` | Vipps **test**-verdi, legg direkte i Render |
| `VIPPS_CLIENT_SECRET` | Vipps **test**-verdi, legg direkte i Render |
| `VIPPS_SUBSCRIPTION_KEY` | Vipps **test**-verdi, legg direkte i Render |
| `VIPPS_SANDBOX_ACCESS_TOKEN` | Tilfeldig hemmelig streng, minst 32 tegn, legg direkte i Render |

Ingen `EUROBATE_*`, `TELL_*`, `TRIPLETEX_*`, `BACKUP_*`, `AWS_*` eller `S3_*` variabler eller miljøgrupper. Tjenesten nekter å starte hvis noen av dem finnes. `DATA_DIR` ligger i midlertidig lagring; testdata kan gå tapt ved omstart.

## Oppførsel

- Kun `POST /vipps/checkout`, `POST /vipps/callback/v2/payments/:orderId`, `GET /vipps/order-status/:orderId`, `GET /vipps/sandbox-result/:orderId`, `GET /vipps/sandbox-auth-check` og test-retursiden er tilgjengelige.
- Checkout og status krever `x-sandbox-token`. Callback er offentlig fordi Vipps må nå den, men status kontrolleres mot Vipps test-API før medlem aktiveres.
- Checkout godtar bare `TEST_BINDING_12M`, navn som starter med `Test`, e-post på `@example.invalid`, og beløp 1 kr i testmiljøet. Testplanen har 12 måneders binding.
- SMS, dørstyring, Tripletex, admin og backup er utilgjengelige. Velkomst-SMS og Tripletex-synk er også sperret inne i betalingsflyten.
- En reservasjon vises som ubetalt. Først bekreftet belastning aktiverer testmedlemmet og lagrer betalingsdag og bindeslutt.
- Den beskyttede `sandbox-auth-check` ber bare Vipps test-API om et tilgangstoken og svarer uten å vise tokenet. Den oppretter ingen ordre.
- Den beskyttede `sandbox-result` viser kun testordrens betalingsstatus og lagrede bindingsdatoer, uten navn eller kontaktopplysninger. Den leser bare testserverens lokale filer.

## Før en faktisk testbetaling

Kontroller Render-oppsettet og de maskerte nøklene direkte i Render. Få uttrykkelig klarsignal før en Vipps-testbetaling startes. Del aldri nøklene i chatten. Koden ligger på GitHub. Testserveren stopper foreløpig ved oppstart fordi de tre Vipps-testnøklene mangler; det er tilsiktet. Ingen testbetaling er startet.
