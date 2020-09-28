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

// Package checklocks performs lock analysis to identify and flag unprotected
// access to field annotated with a '// +checklocks:<mutex-name>' annotation.
//
// For detailed ussage refer to README.md in the same directory.
package checklocks

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"log"
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

type customLogger struct {
	verbose bool
}

var logger = &customLogger{verbose: true}

func (l *customLogger) debugf(fmt string, args ...interface{}) {
	if l.verbose {
		log.Printf(fmt, args...)
	}
}

// Analyzer is the main entrypoint.
var Analyzer = &analysis.Analyzer{
	Name:      "checklocks",
	Doc:       "checks lock preconditions on functions and fields",
	Run:       run,
	Requires:  []*analysis.Analyzer{buildssa.Analyzer},
	FactTypes: []analysis.Fact{(*lockFieldFacts)(nil), (*lockFunctionFacts)(nil)},
}

// structsWithFacts tracks struct types which have exported facts.
var structsWithFacts = make(map[*types.Struct]struct{})

// lockFieldFacts apply on every struct field.
type lockFieldFacts struct {
	// GuardedBy tracks the names and number of fields that guard this field.
	GuardedBy map[string]int

	// IsMutex is true if the field is of type sync.Mutex.
	IsMutex bool

	// IsRWMutex is true if the field is of type sync.RWMutex.
	IsRWMutex bool

	// FieldNum is the number of this field in the struct.
	FieldNum int
}

// AFact implements analysis.Fact.AFact.
func (*lockFieldFacts) AFact() {}

// lockFunctionFacts apply on every method.
type lockFunctionFacts struct {
	// GuardedBy tracks the names and number of receiver fields that guard calls
	// to this function.
	GuardedBy map[string]int
}

// AFact implements analysis.Fact.AFact.
func (*lockFunctionFacts) AFact() {}

type positionKey string

func toPositionKey(position token.Position) positionKey {
	return positionKey(fmt.Sprintf("%s:%d", position.Filename, position.Line))
}

type failData struct {
	pos   token.Pos
	count int
}

func (f failData) String() string {
	return fmt.Sprintf("pos: %d, count: %d", f.pos, f.count)
}

type passContext struct {
	pass *analysis.Pass

	// exemptions tracks functions that should be exempted from lock checking due
	// to '// +checklocks:ignore' annotation.
	exemptions map[types.Object]struct{}

	failures map[positionKey]*failData
}

func (pc *passContext) extractFieldAnnotations(field *ast.Field, fieldType *types.Var) *lockFieldFacts {
	lff := &lockFieldFacts{GuardedBy: make(map[string]int)}
	s := fieldType.Type().String()
	// We use HasSuffix below because fieldType can be fully qualified with the
	// package name eg for the gvisor sync package mutex fields have the type:
	// "gvisor.dev/gvisor/pkg/sync/sync.Mutex"
	switch {
	case strings.HasSuffix(s, "sync.Mutex"):
		lff.IsMutex = true
	case strings.HasSuffix(s, "sync.RWMutex"):
		lff.IsRWMutex = true
	default:
	}
	if field.Doc == nil {
		return lff
	}
	for _, l := range field.Doc.List {
		if strings.HasPrefix(l.Text, "// +checklocks:") {
			guardName := strings.TrimPrefix(l.Text, "// +checklocks:")
			if _, ok := lff.GuardedBy[guardName]; ok {
				pc.pass.Reportf(field.Pos(), "annotation %s specified more than once.", l.Text)
				continue
			}
			lff.GuardedBy[guardName] = -1
		}
	}

	return lff
}

func (pc *passContext) findField(v ssa.Value, field int) types.Object {
	structType, ok := v.Type().Underlying().(*types.Struct)
	if !ok {
		structType = v.Type().Underlying().(*types.Pointer).Elem().Underlying().(*types.Struct)
	}
	return structType.Field(field)
}

// findAndExportStructFacts finds any struct fields that are annotated with the
// "// +checklocks:" annotation and exports relevant facts about the fields to
// be used in later analysis.
func (pc *passContext) findAndExportStructFacts(ss *ast.StructType, structType *types.Struct) {
	type fieldRef struct {
		fieldObj *types.Var
		facts    *lockFieldFacts
	}
	mutexes := make(map[string]*fieldRef)
	rwMutexes := make(map[string]*fieldRef)
	guardedFields := make(map[string]*fieldRef)
	for i, field := range ss.Fields.List {
		fieldObj := structType.Field(i)
		lff := pc.extractFieldAnnotations(field, fieldObj)
		lff.FieldNum = i
		ref := &fieldRef{fieldObj, lff}
		if lff.IsMutex {
			mutexes[fieldObj.Name()] = ref
		}
		if lff.IsRWMutex {
			rwMutexes[fieldObj.Name()] = ref
		}
		if len(lff.GuardedBy) != 0 {
			guardedFields[fieldObj.Name()] = ref
		}
	}

	// Only export annotations if there are some fields guarded w/ the checklocks
	// annotation in the struture.
	if len(guardedFields) == 0 {
		return
	}

	structsWithFacts[structType] = struct{}{}
	// Export facts about all mutexes.
	for _, f := range mutexes {
		pc.pass.ExportObjectFact(f.fieldObj, f.facts)
	}
	// Export facts about all rwMutexes.
	for _, f := range rwMutexes {
		pc.pass.ExportObjectFact(f.fieldObj, f.facts)
	}

	// Validate that guarded fields annotations refer to actual mutexes or
	// rwMutexes in the struct.
	for _, gf := range guardedFields {
		for g := range gf.facts.GuardedBy {
			if f, ok := mutexes[g]; ok {
				gf.facts.GuardedBy[g] = f.facts.FieldNum
			} else if f, ok := rwMutexes[g]; ok {
				gf.facts.GuardedBy[g] = f.facts.FieldNum
			} else {
				pc.pass.Reportf(gf.fieldObj.Pos(), "invalid mutex guard, no such mutex %s in struct %s", g, structType.String())
				continue
			}
			// Export guarded field fact.
			pc.pass.ExportObjectFact(gf.fieldObj, gf.facts)
		}
	}
}

func (pc *passContext) findAndExportFuncFacts(d *ast.FuncDecl) {
	// for each function definition, check for +checklocks:mu annotation, which
	// means that the function must be called with that lock held.
	fnObj := pc.pass.TypesInfo.ObjectOf(d.Name)
	funcFacts := lockFunctionFacts{GuardedBy: make(map[string]int)}
outerLoop:
	for _, l := range d.Doc.List {
		if strings.HasPrefix(l.Text, "// +checklocks:ignore") {
			pc.exemptions[fnObj] = struct{}{}
			return
		}
		if strings.HasPrefix(l.Text, "// +checklocks:") {
			guardName := strings.TrimPrefix(l.Text, "// +checklocks:")
			if _, ok := funcFacts.GuardedBy[guardName]; ok {
				pc.pass.Reportf(l.Pos(), "annotation %s specified more than once.", l.Text)
				continue
			}
			rExpr, ok := d.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			structType := pc.pass.TypesInfo.TypeOf(rExpr.X).Underlying().(*types.Struct)
			found := false
			for i := 0; i < structType.NumFields(); i++ {
				if structType.Field(i).Name() == guardName {
					var lff lockFieldFacts
					pc.pass.ImportObjectFact(structType.Field(i), &lff)
					if !lff.IsMutex && !lff.IsRWMutex {
						pc.pass.Reportf(l.Pos(), "field %s is not a mutex or an rwmutex", structType.Field(i))
						continue outerLoop
					}
					funcFacts.GuardedBy[guardName] = i
					found = true
					break
				}
			}
			if !found {
				pc.pass.Reportf(l.Pos(), "annotation refers to a non-existent field %s in %s", guardName, structType)
				continue
			}
		}
	}
	if len(funcFacts.GuardedBy) == 0 {
		return
	}
	funcObj, ok := pc.pass.TypesInfo.Defs[d.Name].(*types.Func)
	if !ok {
		panic(fmt.Sprintf("function type information missing for %+v", d))
	}
	pc.pass.ExportObjectFact(funcObj, &funcFacts)
}

type mutexState struct {
	// lockedMutexes is used to track which mutexes in a given struct are
	// currently locked using the field number of the mutex as the key.
	lockedMutexes map[int]struct{}
}

// locksHeld tracks all currently held locks.
type locksHeld struct {
	locks map[ssa.Value]*mutexState
}

// Same returns true if the locks held by other and l are the same.
func (l *locksHeld) Same(other *locksHeld) bool {
	return reflect.DeepEqual(l, other)
}

// Copy creates a copy of all the lock state held by l.
func (l *locksHeld) Copy() *locksHeld {
	out := &locksHeld{locks: make(map[ssa.Value]*mutexState)}
	for ssaVal, mState := range l.locks {
		newLM := make(map[int]struct{})
		for k, v := range mState.lockedMutexes {
			newLM[k] = v
		}
		out.locks[ssaVal] = &mutexState{lockedMutexes: newLM}
	}
	return out
}

// checkBasicBlocks traverses the control flow graph starting at a set of given
// block and checks each instruction for allowed operations.
func (pc *passContext) checkBasicBlocks(blocks []*ssa.BasicBlock, recoverBlock *ssa.BasicBlock) {
	if len(blocks) == 0 {
		return
	}

	// mutexes is used to track currently locked sync.Mutexes/sync.RWMutexes for a
	// given *struct identified by ssa.Value.
	seen := make(map[*ssa.BasicBlock]*locksHeld)
	var scan func(block *ssa.BasicBlock, parent *locksHeld)
	scan = func(block *ssa.BasicBlock, parent *locksHeld) {
		_, isExempted := pc.exemptions[block.Parent().Object()]
		if oldLocksHeld, ok := seen[block]; ok {
			if oldLocksHeld.Same(parent) {
				return
			}
			pc.maybeFail(block.Instrs[0].Pos(), isExempted, "failure entering a block %+v with different sets of lock held, oldLocks: %+v, parentLocks: %+v", block, oldLocksHeld, parent)
			return
		}
		seen[block] = parent
		var lh *locksHeld = parent.Copy()
		for _, inst := range block.Instrs {
			pc.checkInstruction(inst, isExempted, lh)
		}
		for _, b := range block.Succs {
			scan(b, lh)
		}
	}
	scan(blocks[0], &locksHeld{locks: make(map[ssa.Value]*mutexState)})
	// Validate that all blocks were touched.
	for _, b := range blocks {
		if _, ok := seen[b]; !ok && recoverBlock != nil && b != recoverBlock {
			panic(fmt.Sprintf("block %+v was not visited during checkBasicBlocks", b))
		}
	}
}

func (pc *passContext) checkInstruction(inst ssa.Instruction, isExempted bool, lh *locksHeld) {
	logger.debugf("checking instruction: %s, isExempted: %t", inst, isExempted)
	switch x := inst.(type) {
	case *ssa.Field:
		pc.checkFieldAccess(inst, x.X, x.Field, isExempted, lh)
	case *ssa.FieldAddr:
		pc.checkFieldAccess(inst, x.X, x.Field, isExempted, lh)
	case *ssa.Call:
		// See: https://godoc.org/golang.org/x/tools/go/ssa#CallInstruction for
		// details on what fields are valid when the Call is an interface dispatch
		// vs regular function invocation.
		if !x.Call.IsInvoke() {
			// We only support lock checking via function calls right now, skip any
			// interface calls.
			pc.checkFunctionCall(x, isExempted, lh)
		}
	}
}

func findField(v ssa.Value, field int) types.Object {
	structType, ok := v.Type().Underlying().(*types.Struct)
	if !ok {
		structType = v.Type().Underlying().(*types.Pointer).Elem().Underlying().(*types.Struct)
	}
	return structType.Field(field)
}

func (pc *passContext) maybeFail(pos token.Pos, isExempted bool, fmtStr string, args ...interface{}) {
	posKey := toPositionKey(pc.pass.Fset.Position(pos))
	logger.debugf("maybeFail: pos: %d, positionKey: %s", pos, posKey)
	if fData, ok := pc.failures[posKey]; ok {
		fData.count--
		if fData.count == 0 {
			delete(pc.failures, posKey)
		}
		return
	}
	if !isExempted {
		pc.pass.Reportf(pos, fmt.Sprintf(fmtStr, args...))
	}
}

func (pc *passContext) checkFieldAccess(inst ssa.Instruction, structObj ssa.Value, field int, isExempted bool, lh *locksHeld) {
	var lff lockFieldFacts
	fieldObj := findField(structObj, field)
	pc.pass.ImportObjectFact(fieldObj, &lff)
	logger.debugf("fieldObj: %s, lff: %+v", fieldObj, lff)
	for _, guardFieldNum := range lff.GuardedBy {
		guardObj := findField(structObj, guardFieldNum)
		var guardlff lockFieldFacts
		pc.pass.ImportObjectFact(guardObj, &guardlff)
		logger.debugf("guardObj: %s, guardLFF: %+v", guardObj, guardlff)
		if guardlff.IsMutex || guardlff.IsRWMutex {
			logger.debugf("guard is a mutex")
			m, ok := lh.locks[structObj]
			if !ok {
				pc.maybeFail(inst.Pos(), isExempted, "invalid field access, %s must be locked when accessing %s", guardObj.Name(), fieldObj.Name())
				continue
			}
			if _, ok := m.lockedMutexes[guardlff.FieldNum]; !ok {
				pc.maybeFail(inst.Pos(), isExempted, "invalid field access, %s must be locked when accessing %s", guardObj.Name(), fieldObj.Name())
			}
		} else {
			panic("incorrect guard that is not a mutex or an RWMutex")
		}
	}
}

func (pc *passContext) checkFunctionCall(call *ssa.Call, isExempted bool, lh *locksHeld) {
	// See: https://godoc.org/golang.org/x/tools/go/ssa#CallCommon
	//
	// 1. "call" mode: when Method is nil (!IsInvoke), a CallCommon represents an ordinary
	//  function call of the value in Value, which may be a *Builtin, a *Function or any
	//  other value of kind 'func'.
	//
	// 	Value may be one of:
	// (a) a *Function, indicating a statically dispatched call
	// to a package-level function, an anonymous function, or
	// a method of a named type.
	//
	// (b) a *MakeClosure, indicating an immediately applied
	// function literal with free variables.
	//
	// (c) a *Builtin, indicating a statically dispatched call
	// to a built-in function.
	//
	// (d) any other value, indicating a dynamically dispatched
	//     function call.
	fn, ok := call.Common().Value.(*ssa.Function)
	if !ok {
		return
	}

	// Check if the function should be called with any locks held.
	// If its a method call.
	if fn.Signature.Recv() != nil {
		var funcFact lockFunctionFacts
		pc.pass.ImportObjectFact(fn.Object(), &funcFact)
		if len(funcFact.GuardedBy) > 0 {
			// Receiver is always the second operand. The first is the method.
			r := (*call.Value().Operands(nil)[1])
			for _, guardFieldNum := range funcFact.GuardedBy {
				guardObj := findField(r, guardFieldNum)
				var lff lockFieldFacts
				pc.pass.ImportObjectFact(guardObj, &lff)
				if lff.IsMutex || lff.IsRWMutex {
					heldMutexes, ok := lh.locks[r]
					if !ok {
						pc.maybeFail(call.Pos(), isExempted, "invalid function call %s must be held", guardObj.Name())
						continue
					}
					if _, ok := heldMutexes.lockedMutexes[guardFieldNum]; !ok {
						pc.maybeFail(call.Pos(), isExempted, "invalid function call %s must be held", guardObj.Name())
					}
				} else {
					panic(fmt.Sprintf("function: %+v has an invalid guard that is not a mutex: %+v", fn, guardObj))
				}
			}
		}
	}

	// Check if it's a method dispatch for something in the sync package.
	// See: https://godoc.org/golang.org/x/tools/go/ssa#Function
	if fn.Package() != nil && fn.Package().Pkg.Name() == "sync" && fn.Signature.Recv() != nil {
		r, ok := call.Common().Args[0].(*ssa.FieldAddr)
		if !ok {
			return
		}
		guardObj := findField(r.X, r.Field)
		var lff lockFieldFacts
		pc.pass.ImportObjectFact(guardObj, &lff)
		if lff.IsMutex || lff.IsRWMutex {
			switch fn.Name() {
			case "Lock", "RLock":
				var m *mutexState
				m, ok = lh.locks[r.X]
				if !ok {
					m = &mutexState{lockedMutexes: make(map[int]struct{})}
				}
				if _, ok := m.lockedMutexes[r.Field]; ok {
					// Double locking a mutex that is already locked.
					pc.maybeFail(call.Pos(), isExempted, "trying to a lock %s when already locked", guardObj.Name())
					return
				}
				m.lockedMutexes[r.Field] = struct{}{}
				lh.locks[r.X] = m
			case "Unlock", "RUnlock":
				m, ok := lh.locks[r.X]
				if !ok {
					pc.maybeFail(call.Pos(), isExempted, "trying to unlock a mutex %s that is already unlocked", guardObj.Name())
					return
				}
				delete(m.lockedMutexes, r.Field)
				if len(m.lockedMutexes) == 0 {
					delete(lh.locks, r.X)
				}
			case "RLocker", "DowngradeLock", "TryLock":
				// we explicitly ignore this for now.
			default:
				panic(fmt.Sprintf("unexpected mutex/rwmutex method invoked: %s", fn.Name()))
			}
		}
	}
}

func run(pass *analysis.Pass) (interface{}, error) {
	pc := &passContext{
		pass:       pass,
		exemptions: make(map[types.Object]struct{}),
		failures:   make(map[positionKey]*failData),
	}
	// Find all struct declarations and export any relevant facts.
	for _, f := range pass.Files {
		for _, decl := range f.Decls {
			d, ok := decl.(*ast.GenDecl)
			// A GenDecl node (generic declaration node) represents an import,
			// constant, type or variable declaration.  We only care about struct
			// declarations so skip any declaration that doesn't declare a new type.
			if !ok || d.Tok != token.TYPE {
				continue
			}

			for _, gs := range d.Specs {
				ts := gs.(*ast.TypeSpec)
				ss, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				structType := pass.TypesInfo.TypeOf(ts.Name).Underlying().(*types.Struct)
				pc.findAndExportStructFacts(ss, structType)
			}
		}
	}

	// Find all method calls and export any relevant facts.
	for _, f := range pass.Files {
		for _, decl := range f.Decls {
			d, ok := decl.(*ast.FuncDecl)
			// Ignore any non function declarations and any functions that do not have
			// any comments.
			if !ok || d.Doc == nil {
				continue
			}
			pc.findAndExportFuncFacts(d)
		}
	}

	// Find all line failure annotations.
	for _, f := range pass.Files {
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if strings.Contains(c.Text, "// +checklocks:fail") {
					cnt := 1
					if strings.Contains(c.Text, "// +checklocks:fail:") {
						parts := strings.SplitAfter(c.Text, "// +checklocks:fail:")
						parsedCount, err := strconv.Atoi(parts[1])
						if err != nil {
							pc.pass.Reportf(c.Pos(), "invalid checklocks annotation : %s", err)
							continue
						}
						cnt = parsedCount
					}
					position := pass.Fset.Position(c.Pos())
					pc.failures[toPositionKey(position)] = &failData{pos: c.Pos(), count: cnt}
				}
			}
		}
	}

	// log all known facts and all failures if debug logging is enabled.
	allFacts := pass.AllObjectFacts()
	for i := range allFacts {
		logger.debugf("fact.object: %+v, fact.Fact: %+v", allFacts[i].Object, allFacts[i].Fact)
	}
	logger.debugf("all expected failures: %+v", pc.failures)

	// Scan all code looking for invalid accesses.
	state := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
	for _, fn := range state.SrcFuncs {
		// We only care about named functions as any anonymous/lambda functions will
		// be checked when walking the blocks for the named function.
		if fn.Object() != nil {
			var funcFact lockFunctionFacts
			pc.pass.ImportObjectFact(fn.Object(), &funcFact)
			if len(funcFact.GuardedBy) > 0 {
				// Skip any functions that have a mutex guard as we will check it's usage
				// when walking the control flow graph of a function that calls the
				// guarded function. Analysis of the function itself will fail immediately
				// as the required mutex will not be held.
				continue
			}
			// If it's a method call only bother checking it if the receiver has
			// annotations.
			if r := fn.Signature.Recv(); r != nil {
				var structType *types.Struct
				var ok bool
				if structType, ok = r.Type().Underlying().(*types.Struct); !ok {
					ptrType, ok := r.Type().Underlying().(*types.Pointer)
					if !ok {
						// Receiver is not a struct or a pointer to a struct
						continue
					}
					structType, ok = ptrType.Elem().Underlying().(*types.Struct)
					if !ok {
						// Receiver is not a struct or a pointer to a struct.
						continue
					}
				}
				if _, ok := structsWithFacts[structType]; !ok {
					continue
				}
			}
		}
		logger.debugf("checking function: %s", fn)
		if fn.Recover != nil {
			pc.checkBasicBlocks([]*ssa.BasicBlock{fn.Recover}, nil)
		}
		pc.checkBasicBlocks(fn.Blocks, fn.Recover)
	}

	// Scan for remaining failures we expect.
	for _, failure := range pc.failures {
		// We are missing expect failures, report as much as possible.
		pass.Reportf(failure.pos, "expected %d failures", failure.count)
	}

	return nil, nil
}
