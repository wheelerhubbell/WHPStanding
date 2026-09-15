# Historical development runs

These logs preserve earlier executions, including failures. They are not the final release verdict.

The first run recorded a SQLite positional-parameter binding defect. The SQLite adapter was corrected to map each PostgreSQL-style `$n` placeholder occurrence to its corresponding SQLite positional parameter. Later runs preserve the growing test coverage as the buyer, HTTP, governance, rail and schema paths were implemented.

The controlling packaged verification is `../verification.json` and its actual `../tests.tap`, executed after the final source edits. The release does not relabel the failed first run as successful.
