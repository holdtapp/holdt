# Real-account Reminders probe

**Question:** do this account's real Reminders lists appear over CalDAV?

```bash
ICLOUD_EMAIL='you@icloud.com' ICLOUD_APP_PASSWORD='abcd-efgh-ijkl-mnop' \
EXPECTED_LISTS='Reminders,Groceries,Family' npm run probe:reminders
```

- Credentials come only from env vars. Output is redacted, and the script never deletes anything.
- `EXPECTED_LISTS` holds the list names exactly as they appear in the iPhone Reminders app.
- **Optional:** `PROBE_WRITE=yes` adds one reminder, "Grok Bot probe (safe to delete)", to the first CalDAV list. Check whether it appears on the iPhone within a minute, then delete it on the phone.

**Verdicts:**

| Verdict | What it means |
|---|---|
| `NO_CALDAV_LISTS` | Real Reminders can't be reached this way, which is the expected result for upgraded Reminders. Calendar still works |
| `PARTIAL` | Some named lists are missing. The visible ones are likely old pre-upgrade CalDAV lists |
| `REAL_LISTS_VISIBLE` | Every named list is visible. Compare the open counts to the phone, and use `PROBE_WRITE` to confirm sync both ways |
| `LISTS_VISIBLE_UNVERIFIED` | Lists are visible, but you didn't name the ones to compare against |
| `AUTH_FAILED` / `ERROR` | Plain-English fix printed |

**Sources:** BusyCal https://www.busymac.com/docs/faqs/112990-reminders-in-ios-13-and-macos-catalina-drops-support-for-caldav/ and 2Do https://www.2doapp.com/docs/faqs/data-deleted-after-ios-13-catalina-upgrade/ both say upgraded lists leave CalDAV. Lingnik/icloud-reminders-mcp claims otherwise, which is why this probe exists.
