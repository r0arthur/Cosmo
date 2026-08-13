---
name: python-sql-injection
description: Flag string-built SQL reaching a database sink in Python
applies_to:
  - "**/*.py"
---
Flag SQL statements assembled with string concatenation, `%`, `.format()`, or
f-strings when the result reaches a database execution sink (`cursor.execute`,
`db.execute`, `session.execute`, raw `text(...)`). Parameterized queries
(placeholders + a params argument) are safe and should not be flagged.

Prefer a concrete exploit scenario (what an attacker controls, where it lands)
over a generic "possible SQL injection" note.
