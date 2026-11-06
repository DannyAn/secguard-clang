//go:build !nosqlite

package db

import (
	"context"
	"testing"
)

func TestStore_DeleteFileCascades(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	fileID, err := s.InsertFile(ctx, &File{Path: "delete_me.c", LOC: 10})
	if err != nil {
		t.Fatalf("InsertFile: %v", err)
	}
	funcID, err := s.InsertFunction(ctx, &Function{
		FileID: fileID, Name: "f", Signature: "f()", StartLine: 1, EndLine: 5,
	})
	if err != nil {
		t.Fatalf("InsertFunction: %v", err)
	}
	_, err = s.InsertFunctionDeclaration(ctx, &FunctionDeclaration{
		FileID: fileID, Name: "g", Signature: "g()", StartLine: 7,
	})
	if err != nil {
		t.Fatalf("InsertFunctionDeclaration: %v", err)
	}

	if err := s.DeleteFile(ctx, fileID); err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}

	f, err := s.GetFileByID(ctx, fileID)
	if err != nil {
		t.Fatalf("GetFileByID after delete: %v", err)
	}
	if f != nil {
		t.Fatal("GetFileByID after delete should return nil")
	}

	fns, err := s.ListFunctionsByFile(ctx, fileID)
	if err != nil {
		t.Fatalf("ListFunctionsByFile after delete: %v", err)
	}
	if len(fns) != 0 {
		t.Fatalf("ListFunctionsByFile after delete should be empty, got %d", len(fns))
	}

	fn, err := s.GetFunctionByID(ctx, funcID)
	if err != nil {
		t.Fatalf("GetFunctionByID after delete: %v", err)
	}
	if fn != nil {
		t.Fatal("GetFunctionByID after delete should return nil")
	}

	decls, err := s.ListFunctionDeclarations(ctx)
	if err != nil {
		t.Fatalf("ListFunctionDeclarations after delete: %v", err)
	}
	for _, d := range decls {
		if d.FileID == fileID {
			t.Fatalf("declaration for deleted file survived: %+v", d)
		}
	}
}

func TestStore_DeleteFileNotFound(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	err := s.DeleteFile(ctx, 999999)
	if err == nil {
		t.Fatal("DeleteFile on nonexistent id should return error")
	}
}
