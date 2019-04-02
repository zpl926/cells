/*
 * Copyright (c) 2018. Abstrium SAS <team (at) pydio.com>
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

// Package sql provides tools and DAOs for speaking SQL as well as managing tables migrations
package sql

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/pydio/cells/common"
	"github.com/pydio/cells/common/dao"
)

var (
	ErrNoRows = sql.ErrNoRows
)

// DAO interface definition
type DAO interface {
	dao.DAO

	DB() *sql.DB
	Prepare(string, interface{}) error
	GetStmt(string, ...interface{}) *sql.Stmt
	GetStmtWithArgs(string, ...interface{}) (*sql.Stmt, []interface{}, error)
	UseExclusion()
	Lock()
	Unlock()
}

// Handler for the main functions of the DAO
type Handler struct {
	dao.DAO

	stmts         map[string]string
	ifuncs        map[string]func(...interface{}) string // TODO - replace next with this
	funcs         map[string]func(...string) string      // Queries that need to be run before we get a statement
	funcsWithArgs map[string]func(...string) (string, []interface{})

	prepared     map[string]*sql.Stmt
	preparedLock *sync.RWMutex

	mu       atomic.Value
	replacer *strings.Replacer
}

func NewDAO(driver string, dsn string, prefix string) DAO {
	conn, err := dao.NewConn(driver, dsn)
	if err != nil {
		return nil
	}
	// Special case for sqlite, we use a mutex to simulate locking as sqlite's locking is not quite up to the task
	var mu atomic.Value
	if driver == "sqlite3" {
		mu.Store(&sync.Mutex{})
	}
	return &Handler{
		DAO:           dao.NewDAO(conn, driver, prefix),
		stmts:         make(map[string]string),
		ifuncs:        make(map[string]func(...interface{}) string),
		funcs:         make(map[string]func(...string) string),
		funcsWithArgs: make(map[string]func(...string) (string, []interface{})),
		prepared:      make(map[string]*sql.Stmt),
		preparedLock:  new(sync.RWMutex),
		replacer:      strings.NewReplacer("%%PREFIX%%", prefix, "%PREFIX%", prefix),
		mu:            mu,
	}
}

func (h *Handler) Init(c common.ConfigValues) error {
	return nil
}

// DB returns the sql DB object
func (h *Handler) DB() *sql.DB {
	return h.GetConn().(*sql.DB)
}

// Prepare the statements that can be used by the DAO
func (h *Handler) Prepare(key string, query interface{}) error {
	switch v := query.(type) {
	case func(...interface{}) string:
		h.ifuncs[key] = v
	case func(...string) string:
		h.funcs[key] = v
	case func(...string) (string, []interface{}):
		h.funcsWithArgs[key] = v
	case string:
		v = h.replacer.Replace(v)
		h.stmts[key] = v
	}

	return nil
}

func (h *Handler) addStmt(query string) (*sql.Stmt, error) {
	stmt, err := h.DB().Prepare(query)
	if err != nil {
		return nil, err
	}

	if h.Driver() == "sqlite3" {
		// We don't keep statements open with sqlite3
		return stmt, nil
	}

	h.preparedLock.Lock()
	defer h.preparedLock.Unlock()

	h.prepared[query] = stmt
	return stmt, nil
}

func (h *Handler) readStmt(query string) *sql.Stmt {
	h.preparedLock.RLock()
	defer h.preparedLock.RUnlock()

	if stmt, ok := h.prepared[query]; ok {
		return stmt
	}

	return nil
}

func (h *Handler) getStmt(query string) (*sql.Stmt, error) {
	if stmt := h.readStmt(query); stmt != nil {
		return stmt, nil
	}

	return h.addStmt(query)
}

// GetStmt returns a list of all statements used by the dao
func (h *Handler) GetStmt(key string, args ...interface{}) *sql.Stmt {
	if v, ok := h.stmts[key]; ok {
		stmt, err := h.getStmt(v)
		if err != nil {
			fmt.Println(err)
			return nil
		}
		return stmt
	}
	if v, ok := h.ifuncs[key]; ok {

		query := v(args...)
		query = h.replacer.Replace(query)

		stmt, err := h.getStmt(query)
		if err != nil {
			fmt.Println(err)
			return nil
		}
		return stmt
	}
	if v, ok := h.funcs[key]; ok {
		var sargs []string
		for _, s := range args {
			sargs = append(sargs, fmt.Sprintf("%v", s))
		}
		query := v(sargs...)
		query = h.replacer.Replace(query)

		stmt, err := h.getStmt(query)
		if err != nil {
			return nil
		}
		return stmt
	}

	return nil
}

// GetStmt returns a list of all statements used by the dao
func (h *Handler) GetStmtWithArgs(key string, params ...interface{}) (*sql.Stmt, []interface{}, error) {
	if v, ok := h.funcsWithArgs[key]; ok {
		var sparams []string
		for _, s := range params {
			sparams = append(sparams, fmt.Sprintf("%v", s))
		}
		query, args := v(sparams...)
		query = h.replacer.Replace(query)
		stmt, err := h.getStmt(query)
		if err != nil {
			return nil, nil, err
		}
		if stmt == nil {
			return nil, nil, fmt.Errorf("empty statement")
		}
		return stmt, args, nil
	}

	return nil, nil, fmt.Errorf("cannot find query for " + key)
}

func (h *Handler) UseExclusion() {
}

func (h *Handler) Lock() {
	if current, ok := h.mu.Load().(*sync.Mutex); ok {
		current.Lock()
	}
}

func (h *Handler) Unlock() {
	if current, ok := h.mu.Load().(*sync.Mutex); ok {
		current.Unlock()
	}
}
