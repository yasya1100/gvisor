// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package test is a test package.
package test

import (
	"math/rand"
	"sync"
)

type testCase struct {
	mu sync.Mutex

	// +checklocks:mu
	guardedField int

	// +checklocks:mu
	nestedStruct struct {
		nested1 int
		nested2 int
	}

	secondMu sync.Mutex

	// +checklocks:mu
	// +checklocks:secondMu
	doubleGuardedField int

	unguardedField int

	rwMu sync.RWMutex

	// +checklocks:rwMu
	rwGuardedField int
}

func testAccess() {
	var tc testCase

	// Valid access
	tc.mu.Lock()
	tc.guardedField = 1
	tc.unguardedField = 1
	tc.mu.Unlock()

	// Valid access as unguarded field is not protected by mu.
	tc.unguardedField = 2

	// Invalid access
	tc.guardedField = 2 // +checklocks:fail

	// Invalid read of a guarded field.
	x := tc.guardedField // +checklocks:fail
	_ = x

	// Double guarded field
	tc.mu.Lock()
	tc.secondMu.Lock()
	tc.doubleGuardedField = 1
	tc.secondMu.Unlock()

	// This should fail as we released the secondMu.
	tc.doubleGuardedField = 2 // +checklocks:fail
	tc.mu.Unlock()

	// This should fail as well as now we are not holding any locks.
	// This line triggers two failures one for each mutex, hence the 2 after
	// fail.
	tc.doubleGuardedField = 3 // +checklocks:fail:2

	// Assignment w/ exclusive lock should pass.
	tc.rwMu.Lock()
	tc.rwGuardedField = 1
	tc.rwMu.Unlock()

	// Assignment w/ RWLock should pass as we don't differentiate between
	// Lock/RLock.
	tc.rwMu.RLock()
	tc.rwGuardedField = 2
	tc.rwMu.RUnlock()

	// Assignment w/o hold Lock() should fail.
	tc.rwGuardedField = 3 // +checklocks:fail

	// Reading w/o holding lock should fail.
	x = tc.rwGuardedField + 3 // +checklocks:fail
	_ = x

	// Just a regular function call with no parameters.
	nestedCall()

	// Valid call where a guardedField is passed to a function as a parameter.
	tc.mu.Lock()
	nestedWithGuardByAddr(&tc.guardedField, &tc.unguardedField)
	tc.mu.Unlock()

	// Invalid call where a guardedField is passed to a function as a parameter
	// without holding locks.
	nestedWithGuardByAddr(&tc.guardedField, &tc.unguardedField) // +checklocks:fail

	// Valid call where a guardedField is passed to a function as a parameter.
	tc.mu.Lock()
	nestedWithGuardByValue(tc.guardedField, tc.unguardedField)
	tc.mu.Unlock()

	// Invalid call where a guardedField is passed to a function as a parameter
	// without holding locks.
	nestedWithGuardByValue(tc.guardedField, tc.unguardedField) // +checklocks:fail
}

func nestedWithGuardByAddr(guardedField, unguardedField *int) {
	*guardedField = 4
	*unguardedField = 5
}

func nestedWithGuardByValue(guardedField, unguardedField int) {
	// read the fields to keep SA4009 static analyzer happy.
	_ = guardedField
	_ = unguardedField
	guardedField = 4
	unguardedField = 5
}

func testNestedStructGuards() {
	var tc testCase
	// Valid access with mu held.
	tc.mu.Lock()
	tc.nestedStruct.nested1 = 1
	tc.nestedStruct.nested2 = 2
	tc.mu.Unlock()

	// Invalid access to nested1 wihout holding mu.
	tc.nestedStruct.nested1 = 1 // +checklocks:fail
}

type testCaseMethods struct {
	mu sync.Mutex

	// +checklocks:mu
	guardedField int
}

func (t *testCaseMethods) Method() {
	// Valid access
	t.mu.Lock()
	t.guardedField = 1
	t.mu.Unlock()

	// invalid access
	t.guardedField = 2 // +checklocks:fail
}

// +checklocks:mu
func (t *testCaseMethods) MethodLocked(a, b, c int) {
	t.guardedField = 3
}

// +checklocks:ignore
func (t *testCaseMethods) IgnoredMethod() {
	// Invalid access but should not fail as the function is annotated
	// with "// +checklocks:ignore"
	t.guardedField = 2
}

func testMethodCalls() {
	var tc2 testCaseMethods

	// Valid use, tc2.Method acquires lock.
	tc2.Method()

	// Valid access tc2.mu is held before calling tc2.MethodLocked.
	tc2.mu.Lock()
	tc2.MethodLocked(1, 2, 3)
	tc2.mu.Unlock()

	// Invalid access no locks are being held.
	tc2.MethodLocked(4, 5, 6) // +checklocks:fail
}

func nestedCall() {
	var tc testCase
	var tc2 testCaseMethods
	// Valid tc2 access
	tc2.mu.Lock()
	tc2.guardedField = 1
	tc2.mu.Unlock()

	// Invalid access, wrong mutex is held.
	tc.mu.Lock()
	tc2.guardedField = 2 // +checklocks:fail
	tc.mu.Unlock()
}

type noMutex struct {
	f int
	g int
}

func (n noMutex) method() {
	n.f = 1
	n.f = n.g
}

func testNoMutex() {
	var n noMutex
	n.method()
}

func testMultiple() {
	var tc1, tc2, tc3 testCaseMethods

	tc1.mu.Lock()

	// Valid access we are holding tc1's lock.
	tc1.guardedField = 1

	// Invalid access we are not holding tc2 or tc3's lock.
	tc2.guardedField = 2 // +checklocks:fail
	tc3.guardedField = 3 // +checklocks:fail
	tc1.mu.Unlock()
}

func testConditionalBranchingLocks() {
	var tc2 testCaseMethods
	x := rand.Intn(10)
	if x%2 == 1 {
		tc2.mu.Lock()
	}
	// This is invalid access as tc2.mu is not held if we never entered
	// the if block.
	tc2.guardedField = 1 // +checklocks:fail

	var tc3 testCaseMethods
	if x%2 == 1 {
		tc3.mu.Lock()
	} else {
		tc3.mu.Lock()
	}
	// This is valid as tc3.mu is held in if and else blocks.
	tc3.guardedField = 1
}

type testAnonymousFunction struct {
	mu sync.Mutex

	// +checklocks:mu
	guardedField int
}

func (t *testAnonymousFunction) anonFunctionCall() {
	f := func() {
		t.guardedField = 1 // +checklocks:fail
	}
	f()
}
