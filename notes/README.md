# Notes

Your running log of findings. One file per session or per exercise works well, for example `2026-11-04-stuffing.md`.

A useful shape for each entry:

```markdown
## <scenario> · <date>
- Defences on: …
- Run ids: baseline …, after …
- What got through:
- What fired (and what didn't):
- Why (which signal, which rule, which defence):
- Next thing to try:
```

Run ids let you replay exactly what you saw later: pick one in the dashboard's Run filter, or use it in the SQL queries from the [guide](../docs/GUIDE.md#92-sql-the-telemetry-itself).
