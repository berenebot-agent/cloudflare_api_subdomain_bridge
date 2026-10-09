package main

/*
#cgo LDFLAGS: -lsqlite3
#include <stdlib.h>
#include <sqlite3.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

// Store holds only bridge ownership metadata and audit events. No client secrets are stored.
type Store struct {
	mu sync.Mutex
	db *C.sqlite3
}
type Resource struct {
	Owner   string `json:"owner"`
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	Details string `json:"details,omitempty"`
}

func OpenStore(path string) (*Store, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	var db *C.sqlite3
	if C.sqlite3_open_v2(cpath, &db, C.SQLITE_OPEN_READWRITE|C.SQLITE_OPEN_CREATE|C.SQLITE_OPEN_FULLMUTEX, nil) != C.SQLITE_OK {
		msg := "sqlite open failed"
		if db != nil {
			msg = C.GoString(C.sqlite3_errmsg(db))
			C.sqlite3_close(db)
		}
		return nil, errors.New(msg)
	}
	s := &Store{db: db}
	if err := s.exec(`PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS resources(owner TEXT NOT NULL,kind TEXT NOT NULL,id TEXT PRIMARY KEY,name TEXT NOT NULL,details TEXT NOT NULL DEFAULT ''); CREATE INDEX IF NOT EXISTS resources_owner_kind ON resources(owner,kind); CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT NOT NULL DEFAULT (datetime('now')),owner TEXT NOT NULL,method TEXT NOT NULL,path TEXT NOT NULL,status INTEGER NOT NULL);`); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		C.sqlite3_close(s.db)
		s.db = nil
	}
}
func (s *Store) exec(q string) error {
	c := C.CString(q)
	defer C.free(unsafe.Pointer(c))
	var errmsg *C.char
	rc := C.sqlite3_exec(s.db, c, nil, nil, &errmsg)
	if rc != C.SQLITE_OK {
		msg := C.GoString(errmsg)
		C.sqlite3_free(unsafe.Pointer(errmsg))
		return errors.New(msg)
	}
	return nil
}
func (s *Store) prepare(q string, values ...string) (*C.sqlite3_stmt, error) {
	c := C.CString(q)
	defer C.free(unsafe.Pointer(c))
	var stmt *C.sqlite3_stmt
	if C.sqlite3_prepare_v2(s.db, c, -1, &stmt, nil) != C.SQLITE_OK {
		return nil, errors.New(C.GoString(C.sqlite3_errmsg(s.db)))
	}
	for i, v := range values {
		p := C.CString(v)
		rc := C.sqlite3_bind_text(stmt, C.int(i+1), p, C.int(len(v)), C.SQLITE_TRANSIENT)
		C.free(unsafe.Pointer(p))
		if rc != C.SQLITE_OK {
			C.sqlite3_finalize(stmt)
			return nil, errors.New(C.GoString(C.sqlite3_errmsg(s.db)))
		}
	}
	return stmt, nil
}
func (s *Store) Put(r Resource) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, e := s.prepare(`INSERT INTO resources(owner,kind,id,name,details) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,details=excluded.details WHERE resources.owner=excluded.owner AND resources.kind=excluded.kind`, r.Owner, r.Kind, r.ID, r.Name, r.Details)
	if e != nil {
		return e
	}
	defer C.sqlite3_finalize(st)
	if C.sqlite3_step(st) != C.SQLITE_DONE {
		return errors.New(C.GoString(C.sqlite3_errmsg(s.db)))
	}
	if C.sqlite3_changes(s.db) != 1 {
		return errors.New("resource identifier already belongs to another owner or resource type")
	}
	return nil
}
func (s *Store) Get(owner, kind, id string) (Resource, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, e := s.prepare(`SELECT owner,kind,id,name,details FROM resources WHERE owner=? AND kind=? AND id=?`, owner, kind, id)
	if e != nil {
		return Resource{}, false, e
	}
	defer C.sqlite3_finalize(st)
	if C.sqlite3_step(st) != C.SQLITE_ROW {
		return Resource{}, false, nil
	}
	return resourceRow(st), true, nil
}
func resourceRow(st *C.sqlite3_stmt) Resource {
	return Resource{Owner: C.GoString((*C.char)(unsafe.Pointer(C.sqlite3_column_text(st, 0)))), Kind: C.GoString((*C.char)(unsafe.Pointer(C.sqlite3_column_text(st, 1)))), ID: C.GoString((*C.char)(unsafe.Pointer(C.sqlite3_column_text(st, 2)))), Name: C.GoString((*C.char)(unsafe.Pointer(C.sqlite3_column_text(st, 3)))), Details: C.GoString((*C.char)(unsafe.Pointer(C.sqlite3_column_text(st, 4))))}
}
func (s *Store) List(owner, kind string) ([]Resource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, e := s.prepare(`SELECT owner,kind,id,name,details FROM resources WHERE owner=? AND kind=? ORDER BY name`, owner, kind)
	if e != nil {
		return nil, e
	}
	defer C.sqlite3_finalize(st)
	out := []Resource{}
	for {
		rc := C.sqlite3_step(st)
		if rc == C.SQLITE_DONE {
			break
		}
		if rc != C.SQLITE_ROW {
			return nil, fmt.Errorf("sqlite query failed: %s", C.GoString(C.sqlite3_errmsg(s.db)))
		}
		out = append(out, resourceRow(st))
	}
	return out, nil
}
func (s *Store) Delete(owner, kind, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, e := s.prepare(`DELETE FROM resources WHERE owner=? AND kind=? AND id=?`, owner, kind, id)
	if e != nil {
		return e
	}
	defer C.sqlite3_finalize(st)
	if C.sqlite3_step(st) != C.SQLITE_DONE {
		return errors.New(C.GoString(C.sqlite3_errmsg(s.db)))
	}
	return nil
}
func (s *Store) Audit(owner, method, path string, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, e := s.prepare(`INSERT INTO audit(owner,method,path,status) VALUES(?,?,?,?)`, owner, method, path, fmt.Sprint(status))
	if e == nil {
		C.sqlite3_step(st)
		C.sqlite3_finalize(st)
	}
}
