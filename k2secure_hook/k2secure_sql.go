// Copyright (C) 2022 K2 Cyber Security Inc.

package k2secure_hook

import (
	"context"
	"database/sql"
	"fmt"

	logging "github.com/k2io/go-k2secure/v2/internal/k2secure_logs"
	k2i "github.com/k2io/go-k2secure/v2/k2secure_intercept"
)

type K2DB struct {
	sql.DB
}

//go:noinline
func (k *K2DB) QueryContext_s(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	logger.Debugln("Hook Called : ", "(*sql.DB).QueryContext_s")
	k2i.K2dbquery(query, args...)
	row, err := k.QueryContext_s(ctx, query, args...)
	return row, err
}

//go:noinline
func (k *K2DB) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	logger.Debugln("Hook Called : ", "(*sql.DB).QueryContext")
	eventId := k2i.K2dbquery(query, args...)
	row, err := k.QueryContext_s(ctx, query, args...)
	k2i.SendExitEvent(eventId, err)
	return row, err
}

//go:noinline
func (k *K2DB) ExecContext_s(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	logger.Debugln("Hook Called : ", "(*sql.DB).ExecContext_s")
	k2i.K2dbquery(query, args...)
	result, err := k.ExecContext_s(ctx, query, args...)
	return result, err
}

//go:noinline
func (k *K2DB) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	logger.Debugln("Hook Called : ", "(*sql.DB).ExecContext")
	eventId := k2i.K2dbquery(query, args...)
	result, err := k.ExecContext_s(ctx, query, args...)
	k2i.SendExitEvent(eventId, err)
	return result, err
}

//go:noinline
func (k *K2DB) PrepareContext_s(ctx context.Context, query string) (*sql.Stmt, error) {
	logger.Debugln("Hook Called : ", "(*sql.DB).PrepareContext_s")
	stmt, err := k.PrepareContext_s(ctx, query)
	if stmt != nil {
		myString := fmt.Sprintf("%p", stmt)
		k2i.K2dbprepare(query, myString)
	}
	return stmt, err
}

//go:noinline
func (k *K2DB) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	logger.Debugln("Hook Called : ", "(*sql.DB).PrepareContext")
	stmt, err := k.PrepareContext_s(ctx, query)
	if stmt != nil {
		myString := fmt.Sprintf("%p", stmt)
		k2i.K2dbprepare(query, myString)
	}
	return stmt, err
}

type K2Conn struct {
	sql.Conn
}

//go:noinline
func (k *K2Conn) QueryContext_s(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	logger.Debugln("Hook Called : ", "(*sql.Conn).QueryContext_s")
	k2i.K2dbquery(query, args...)
	rows, err := k.QueryContext_s(ctx, query, args...)
	return rows, err
}

//go:noinline
func (k *K2Conn) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	logger.Debugln("Hook Called : ", "(*sql.Conn).QueryContext")
	eventId := k2i.K2dbquery(query, args...)
	rows, err := k.QueryContext_s(ctx, query, args...)
	k2i.SendExitEvent(eventId, err)
	return rows, err
}

//go:noinline
func (k *K2Conn) ExecContext_s(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	logger.Debugln("Hook Called : ", "(*sql.Conn).ExecContext_s")
	k2i.K2dbquery(query, args...)
	rows, err := k.ExecContext_s(ctx, query, args...)
	return rows, err
}

//go:noinline
func (k *K2Conn) ExecContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	logger.Debugln("Hook Called : ", "(*sql.Conn).ExecContext")
	eventId := k2i.K2dbquery(query, args...)
	rows, err := k.ExecContext_s(ctx, query, args...)
	k2i.SendExitEvent(eventId, err)
	return rows, err
}

//go:noinline
func (k *K2Conn) PrepareContext_s(ctx context.Context, query string) (*sql.Stmt, error) {
	logger.Debugln("Hook Called : ", "(*sql.Conn).PrepareContext_s")
	stmt, err := k.PrepareContext_s(ctx, query)
	if stmt != nil {
		address := fmt.Sprintf("%p", stmt)
		k2i.K2dbprepare(query, address)
	}
	return stmt, err
}

//go:noinline
func (k *K2Conn) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	logger.Debugln("Hook Called : ", "(*sql.Conn).PrepareContext")
	stmt, err := k.PrepareContext_s(ctx, query)
	if stmt != nil {
		address := fmt.Sprintf("%p", stmt)
		k2i.K2dbprepare(query, address)
	}
	return stmt, err
}

type K2Tx struct {
	sql.Tx
}

//go:noinline
func (k *K2Tx) QueryContext_s(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	logger.Debugln("Hook Called : ", "(*sql.K2Tx).QueryContext_s")
	k2i.K2dbquery(query, args...)
	rows, err := k.QueryContext_s(ctx, query, args...)
	return rows, err
}

//go:noinline
func (k *K2Tx) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	logger.Debugln("Hook Called : ", "(*sql.K2Tx).QueryContext")
	eventId := k2i.K2dbquery(query, args...)
	rows, err := k.QueryContext_s(ctx, query, args...)
	k2i.SendExitEvent(eventId, err)
	return rows, err
}

//go:noinline
func (k *K2Tx) ExecContext_s(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	logger.Debugln("Hook Called : ", "(*sql.K2Tx).ExecContext_s")
	k2i.K2dbquery(query, args...)
	rows, err := k.ExecContext_s(ctx, query, args...)
	return rows, err
}

//go:noinline
func (k *K2Tx) ExecContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	logger.Debugln("Hook Called : ", "(*sql.K2Tx).ExecContext")
	eventId := k2i.K2dbquery(query, args...)
	rows, err := k.ExecContext_s(ctx, query, args...)
	k2i.SendExitEvent(eventId, err)
	return rows, err
}

//go:noinline
func (k *K2Tx) PrepareContext_s(ctx context.Context, query string) (*sql.Stmt, error) {
	logger.Debugln("Hook Called : ", "(*sql.K2Tx).PrepareContext_s")
	stmt, err := k.PrepareContext_s(ctx, query)
	if stmt != nil {
		address := fmt.Sprintf("%p", stmt)
		k2i.K2dbprepare(query, address)
	}
	return stmt, err
}

//go:noinline
func (k *K2Tx) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	logger.Debugln("Hook Called : ", "(*sql.K2Tx).PrepareContext")
	stmt, err := k.PrepareContext_s(ctx, query)
	if stmt != nil {
		address := fmt.Sprintf("%p", stmt)
		k2i.K2dbprepare(query, address)
	}
	return stmt, err
}

type K2Stmt struct {
	sql.Stmt
}

//go:noinline
func (k *K2Stmt) ExecContext_s(ctx context.Context, args ...interface{}) (*sql.Rows, error) {
	logger.Debugln("in K2query Stmt ExecContext_s hook")
	myAddress := fmt.Sprintf("%p", k)
	k2i.K2dbexecprepare(myAddress, args...)
	rows, err := k.ExecContext_s(ctx, args...)
	return rows, err
}

//go:noinline
func (k *K2Stmt) ExecContext(ctx context.Context, args ...interface{}) (*sql.Rows, error) {

	logger.Debugln("in K2query Stmt ExecContext hook")
	myAddress := fmt.Sprintf("%p", k)
	eventId := k2i.K2dbexecprepare(myAddress, args...)
	rows, err := k.ExecContext_s(ctx, args...)
	k2i.SendExitEvent(eventId, err)
	return rows, err
}

//go:noinline
func (k *K2Stmt) QueryContext_s(ctx context.Context, args ...interface{}) (*sql.Rows, error) {
	logger.Debugln("Hook Called : ", "(*sql.K2Tx).QueryContext_s")
	myAddress := fmt.Sprintf("%p", k)
	k2i.K2dbexecprepare(myAddress, args...)
	rows, err := k.QueryContext_s(ctx, args...)
	return rows, err
}

//go:noinline
func (k *K2Stmt) QueryContext(ctx context.Context, args ...interface{}) (*sql.Rows, error) {
	logger.Debugln("Hook Called : ", "(*sql.K2Tx).QueryContext")
	myAddress := fmt.Sprintf("%p", k)
	eventId := k2i.K2dbexecprepare(myAddress, args...)
	rows, err := k.QueryContext_s(ctx, args...)
	k2i.SendExitEvent(eventId, err)
	return rows, err
}

func initSqlHook() {

	if debug_drop_hooks || debug_drop_sql_hooks {
		return
	}

	e := k2i.HookWrapInterface((*sql.DB).ExecContext, (*K2DB).ExecContext, (*K2DB).ExecContext_s)
	logging.IsHooked("(*sql.DB).ExecContext", e)
	e = k2i.HookWrapInterface((*sql.DB).QueryContext, (*K2DB).QueryContext, (*K2DB).QueryContext_s)
	logging.IsHooked("(*sql.DB).QueryContext", e)
	e = k2i.HookWrapInterface((*sql.DB).PrepareContext, (*K2DB).PrepareContext, (*K2DB).PrepareContext_s)
	logging.IsHooked("(*sql.DB).PrepareContext", e)

	e = k2i.HookWrapInterface((*sql.Conn).QueryContext, (*K2Conn).QueryContext, (*K2Conn).QueryContext_s)
	logging.IsHooked("(*sql.Conn).QueryContext", e)
	e = k2i.HookWrapInterface((*sql.Conn).PrepareContext, (*K2Conn).PrepareContext, (*K2Conn).PrepareContext_s)
	logging.IsHooked("(*sql.Conn).PrepareContext", e)
	e = k2i.HookWrapInterface((*sql.Conn).ExecContext, (*K2Conn).ExecContext, (*K2Conn).ExecContext_s)
	logging.IsHooked("(*sql.Conn).ExecContext", e)

	e = k2i.HookWrapInterface((*sql.Tx).QueryContext, (*K2Tx).QueryContext, (*K2Tx).QueryContext_s)
	logging.IsHooked("(*sql.Tx).QueryContext", e)
	e = k2i.HookWrapInterface((*sql.Tx).PrepareContext, (*K2Tx).PrepareContext, (*K2Tx).PrepareContext_s)
	logging.IsHooked("(*sql.Tx).PrepareContext", e)
	e = k2i.HookWrapInterface((*sql.Tx).ExecContext, (*K2Tx).ExecContext, (*K2Tx).ExecContext_s)
	logging.IsHooked("(*sql.Tx).ExecContext", e)

	e = k2i.HookWrapInterface((*sql.Stmt).ExecContext, (*K2Stmt).ExecContext, (*K2Stmt).ExecContext_s)
	logging.IsHooked("(*sql.Stmt).ExecContext", e)
	e = k2i.HookWrapInterface((*sql.Stmt).QueryContext, (*K2Stmt).QueryContext, (*K2Stmt).QueryContext_s)
	logging.IsHooked("(*sql.Stmt).QueryContext", e)

	return

}
