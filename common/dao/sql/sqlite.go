/*
 * Copyright (c) 2019-2022. Abstrium SAS <team (at) pydio.com>
 * This file is part of Pydio Cells.
 *
 * Pydio Cells is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Pydio Cells is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Pydio Cells.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The latest code can be found at <https://pydio.com>.
 */

package sql

import (
	"database/sql"

	"github.com/pydio/cells/v4/common/dao"
	// _ "github.com/mattn/go-sqlite3"
)

type sqlite struct {
	conn *sql.DB
}

func (s *sqlite) Open(dsn string) (dao.Conn, error) {
	db, err := getSqlConnection("sqlite3", dsn)
	if err != nil {
		return nil, err
	}

	s.conn = db
	return db, nil
}

func (s *sqlite) GetConn() dao.Conn {
	return s.conn
}

func (s *sqlite) SetMaxConnectionsForWeight(num int) {
	// Not implemented
}
