package main
// INTENTIONAL INSECURE FIXTURE — demo/test only.

import (
        "database/sql"
        "fmt"
        "os/exec"
)

func badQuery(db *sql.DB, id string) {
        db.Query(fmt.Sprintf("SELECT * FROM t WHERE id=%s", id))
}

func badCmd(arg string) {
        exec.Command("sh", "-c", arg).Run()
}
