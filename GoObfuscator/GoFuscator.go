package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
   "unicode"
	log "github.com/sirupsen/logrus"
	"golang.org/x/tools/go/ast/astutil"
)

var (
	srcPath         = flag.String("srcpath", "", "the path to the src directory")
	writeChanges    = flag.Bool("writechanges", false, "write changes to files")
	obfCalls        = flag.Bool("calls", false, "enable randomization of calls and functions")
	obfLoops        = flag.Bool("loops", false, "obfuscate loops by converting to gotos")
	obfStrings      = flag.Bool("strings", false, "obfuscate strings by encryption")
	obfStringKey    = flag.String("stringsKey", "0101010101010101010101010101010101010101010101010101010101010101", "the key for encrypting strings (64 length)")
	obfStringNonce  = flag.String("stringNonce", "010101010101010101010101", "the nonce for encrypting strings (24 length)")
	verbose         = flag.Bool("verbose", false, "be verbose")
	deadcode        = flag.Bool("deadcode", false, "add some deadcode")
	letterRunes     = []rune("abcdefghijklmnopqrstuvwxyz")
)

func init() {
	rand.Seed(time.Now().UnixNano())
	log.SetOutput(os.Stdout)
}

func parsedir(fset *token.FileSet, path string, filter func(string) bool, mode parser.Mode) (map[string]*ast.Package, error) {
	list := []string{}
	err := filepath.Walk(path, func(fpath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		list = append(list, fpath)
		return nil
	})
	if err != nil {
		log.Println(err)
	}

	pkgs := make(map[string]*ast.Package)
	for _, filename := range list {
		if strings.HasSuffix(filename, ".go") && (filter == nil || filter(filename)) {
			if *verbose {
				fmt.Printf("Parsing %#v\n", filename)
			}
			src, err := parser.ParseFile(fset, filename, nil, mode)
			if err == nil {
				name := src.Name.Name
				pkg, found := pkgs[name]
				if !found {
					pkg = &ast.Package{
						Name:  name,
						Files: make(map[string]*ast.File),
					}
					pkgs[name] = pkg
				}
				pkg.Files[filename] = src
			} else {
				return nil, err
			}
		}
	}
	return pkgs, nil
}

func main() {
	flag.Parse()

	if srcPath == nil {
		panic("provide --srcpath")
	}

	fset := token.NewFileSet()
	pkgs, err := parsedir(fset, *srcPath, func(d string) bool {
		return true
	}, parser.AllErrors)
	if err != nil {
		panic(err)
	}

	if *deadcode {
		if err := injdeadcode(fset, pkgs); err != nil {
			panic(err)
		}
	}

	if *obfStrings {
		if err := encrypstr(fset, pkgs, *obfStringKey, *obfStringNonce); err != nil {
			panic(err)
		}
	}

	if *obfLoops {
		fortotalpoaslplaslpdplaplsd(fset, pkgs)
	}

	if *obfCalls {
		funcChangeHistory := randomizeCalls(fset, pkgs)
		if *verbose {
			log.Printf("Functions randomized : %v", funcChangeHistory)
		}
	}

	for _, pkg := range pkgs {
		for file, fileast := range pkg.Files {
			buf := new(bytes.Buffer)
			if err := format.Node(buf, fset, fileast); err != nil {
				panic(err)
			}
			fmt.Printf("%s\n", buf.Bytes())
			if *writeChanges {
				ioutil.WriteFile(file, buf.Bytes(), 0644)
			}
		}
	}
}

func gendedcode() ([]ast.Stmt, error) {
	xMin := 1
	xMax := 10
	zXXXinit := rand.Intn(xMax-xMin+1) + xMin
	sXXXinit := rand.Intn(xMax-xMin+1) + xMin
	iXXXinit := rand.Intn(xMax-xMin+1) + xMin

	src := fmt.Sprintf(`
	package main
	func SOMEDEADCODE() {
		(func() {
			zXXX := int64(%d)	
			sXXX := float64(%d)
			for iXXX := %d; iXXX < 15; iXXX++ {
				for jXXX := iXXX; jXXX < 15; jXXX++ {
					for zXXX := jXXX; zXXX < 15; zXXX++ {
						sXXX = (float64(iXXX+ jXXX) * float64(zXXX)) / float64(iXXX);
					}
				}
			}
			if sXXX == float64(zXXX) {
				;
			}
		})()
	}`, zXXXinit, sXXXinit, iXXXinit)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "src.go", src, 0)
	if err != nil {
		return nil, err
	}

	funcDecl, ok := f.Decls[0].(*ast.FuncDecl)
	if !ok {
		return nil, errors.New("failed to cast funcDecl")
	}

	return funcDecl.Body.List, nil
}

func injdeadcode(fset *token.FileSet, pkgs map[string]*ast.Package) error {
	deadcodeAST, err := gendedcode()
	if err != nil {
		return err
	}

	for _, pkg := range pkgs {
		for _, fileast := range pkg.Files {
			astutil.Apply(fileast, func(cr *astutil.Cursor) bool {
				cn, ok := cr.Node().(*ast.FuncDecl)
				if !ok {
					return true
				}

				if *verbose {
					log.Printf("Adding deadcode to %s", cn.Name.Name)
				}
				cn.Body.List = append(deadcodeAST, cn.Body.List...)
				return true
			}, nil)
		}
	}

	return nil
}

func fortotalpoaslplaslpdplaplsd(fset *token.FileSet, pkgs map[string]*ast.Package) map[string]string {
	funcChangeHistory := make(map[string]string)

	for _, pkg := range pkgs {
		for _, fileast := range pkg.Files {
			convertTopLevelFunctionsBodiesLoops(pkg.Name, fileast, funcChangeHistory)
		}
	}

	return funcChangeHistory
}

func convertTopLevelFunctionsBodiesLoops(pkgName string, fileAst *ast.File, changeHistory map[string]string) {
	astutil.Apply(fileAst, func(cr *astutil.Cursor) bool {
		stmtType, ok := cr.Node().(*ast.ForStmt)
		if !ok {
			return true
		}

		init := stmtType.Init
		cond := stmtType.Cond
		post := stmtType.Post
		body := stmtType.Body

		if init == nil || cond == nil || post == nil || body == nil {
			return true
		}

		if *verbose {
			log.Printf("For loop detected (init=%v, cond=%v, post=%v, body=%v)", init, cond, post, body)
		}

		loopInitIdent := ast.NewIdent(fmt.Sprintf("LOOP_INIT_%s", randStringRunes(6)))
		loopCondIdent := ast.NewIdent(fmt.Sprintf("LOOP_COND_%s", randStringRunes(6)))
		loopBodyIdent := ast.NewIdent(fmt.Sprintf("LOOP_BODY_%s", randStringRunes(6)))
		loopEndIdent := ast.NewIdent(fmt.Sprintf("LOOP_END_%s", randStringRunes(6)))

		astutil.Apply(body, func(crn *astutil.Cursor) bool {
			branch, ok := crn.Node().(*ast.BranchStmt)
			if !ok {
				return true
			}
			if branch.Tok == token.BREAK {
				crn.Replace(&ast.BranchStmt{
					Tok:   token.GOTO,
					Label: loopEndIdent,
				})
			}
			return true
		}, nil)

		body.List = append(body.List, post,
			&ast.BranchStmt{
				Tok:   token.GOTO,
				Label: loopCondIdent,
			})

		loopBegStmts := []ast.Stmt{
			&ast.BranchStmt{
				Tok:   token.GOTO,
				Label: loopInitIdent,
			},
		}

		loopInitStmts := []ast.Stmt{
			&ast.LabeledStmt{
				Label: loopInitIdent,
				Stmt:  &ast.EmptyStmt{},
			},
			init,
			&ast.BranchStmt{
				Tok:   token.GOTO,
				Label: loopCondIdent,
			},
		}

		loopCondStmts := []ast.Stmt{
			&ast.LabeledStmt{
				Label: loopCondIdent,
				Stmt: &ast.IfStmt{
					Cond: cond,
					Body: &ast.BlockStmt{
						List: []ast.Stmt{
							&ast.BranchStmt{
								Tok:   token.GOTO,
								Label: loopBodyIdent,
							},
						},
					},
					Else: &ast.BranchStmt{
						Tok:   token.GOTO,
						Label: loopEndIdent,
					},
				},
			},
		}

		loopBodyStmts := []ast.Stmt{
			&ast.LabeledStmt{
				Label: loopBodyIdent,
				Stmt:  body,
			},
		}

		loopEndStmts := []ast.Stmt{
			&ast.LabeledStmt{
				Label: loopEndIdent,
				Stmt:  &ast.BlockStmt{},
			},
		}

		ObfuscationBody := []ast.Stmt{}
		ObfuscationBody = append(ObfuscationBody, loopBegStmts...)
		ObfuscationBody = append(ObfuscationBody, loopInitStmts...)
		ObfuscationBody = append(ObfuscationBody, loopCondStmts...)
		ObfuscationBody = append(ObfuscationBody, loopBodyStmts...)
		ObfuscationBody = append(ObfuscationBody, loopEndStmts...)

		cr.Replace(&ast.BlockStmt{
			List: ObfuscationBody,
		})
		return true
	}, nil)
}

func randomizeCalls(fset *token.FileSet, pkgs map[string]*ast.Package) map[string]string {
	funcChangeHistory := make(map[string]string)

	for _, pkg := range pkgs {
		for _, fileast := range pkg.Files {
			newRandomizeTop(pkg.Name, fileast, funcChangeHistory)
		}
	}

	for _, pkg := range pkgs {
		for _, fileast := range pkg.Files {
			newRandomizeInner(pkg.Name, fileast, funcChangeHistory)
		}
	}

	return funcChangeHistory
}

func newRandomizeInner(pkgName string, fileAst *ast.File, changeHistory map[string]string) {
	astutil.Apply(fileAst, func(cr *astutil.Cursor) bool {
		callExpr, ok := cr.Node().(*ast.CallExpr)
		if !ok {
			return true
		}

		switch fun := callExpr.Fun.(type) {
		case *ast.SelectorExpr:
			ident, ok := fun.X.(*ast.Ident)
			if ok {
				if rname, ok := changeHistory[fmt.Sprintf("%s.%s", ident.Name, fun.Sel.Name)]; ok {
					fun.Sel = ast.NewIdent(rname)
				}
			}
		case *ast.Ident:
			if rname, ok := changeHistory[fmt.Sprintf("%s.%s", pkgName, fun.Name)]; ok {
				fun.Name = rname
			}
		}

		return true
	}, nil)
}

func newRandomizeTop(pkgName string, fileAst *ast.File, changeHistory map[string]string) {
	astutil.Apply(fileAst, func(cr *astutil.Cursor) bool {
		funcDecl, ok := cr.Node().(*ast.FuncDecl)
		if !ok {
			return true
		}

		if funcDecl.Recv != nil || funcDecl.Name.String() == "main" && pkgName == "main" || funcDecl.Name.String() == "init" {
			return true
		}

		outname := fmt.Sprintf("%s.%s", pkgName, funcDecl.Name.String())

		if randomName, ok := changeHistory[outname]; ok {
			funcDecl.Name = ast.NewIdent(randomName)
		} else {
			randomName := randStringRunes(32)
			if isExportedFunction(string(funcDecl.Name.String())) {
				randomName = strings.Title(randomName)
			}
			changeHistory[outname] = randomName
			funcDecl.Name = ast.NewIdent(randomName)
		}

		return true
	}, nil)
}

func isExportedFunction(funcName string) bool {
	if len(funcName) == 0 {
		panic("this should not happen")
		return false
	}

	return unicode.IsUpper(rune(funcName[0]))
}

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
func generateAESDecryptAST(key, nonce string) (*ast.FuncDecl, error) {
	src := fmt.Sprintf(`
	package main
	func AES_DECRYPT(s string) string {
		key, _ := hex.DecodeString("%s")
		ciphertext, _ := hex.DecodeString(s)
		nonce, _ := hex.DecodeString("%s")
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err.Error())
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			panic(err.Error())
		}

		plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			panic(err.Error())
		}
		return string(plaintext)
	}`, key, nonce)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "src.go", src, 0)
	if err != nil {
		return nil, err
	}

	funcDecl, ok := f.Decls[0].(*ast.FuncDecl)
	if !ok {
		return nil, errors.New("failed to cast funcDecl")
	}

	return funcDecl, nil
}

func encrypstr(fset *token.FileSet, pkgs map[string]*ast.Package, key, nonce string) error {
	if len(key) != 64 {
		return errors.New("encryption key invalid length")
	}

	if len(nonce) != 24 {
		return errors.New("encryption nonce invalid length")
	}

	for _, pkg := range pkgs {
		for _, fileast := range pkg.Files {
			nencryptstring(pkg.Name, fileast, key, nonce)
		}
	}

	for _, pkg := range pkgs {
		for _, fileast := range pkg.Files {
			ndecryptstr(pkg.Name, fileast)
		}
	}

	aesDecAST, err := generateAESDecryptAST(key, nonce)
	if err != nil {
		return err
	}

	insertedFunction := false
	for _, pkg := range pkgs {
		for _, fileast := range pkg.Files {
			astutil.Apply(fileast, func(cr *astutil.Cursor) bool {
				if insertedFunction {
					return false
				}
				cn, ok := cr.Node().(*ast.FuncDecl)
				if !ok {
					return true
				}
				if cn.Name.String() != "main" {
					return true
				}
				cr.InsertBefore(aesDecAST)

				astutil.AddImport(fset, fileast, "crypto/aes")
				astutil.AddImport(fset, fileast, "crypto/cipher")
				astutil.AddImport(fset, fileast, "encoding/hex")
				insertedFunction = true
				return false
			}, nil)
		}
	}

	return nil
}

func ndecryptstr(pkgName string, fileAst *ast.File) {
	astutil.Apply(fileAst, func(cr *astutil.Cursor) bool {
		cn, ok := cr.Node().(*ast.BasicLit)
		if !ok {
			return true
		}

		if cn.Kind != token.STRING {
			return true
		}

		assignv, parentAssignOk := cr.Parent().(*ast.AssignStmt)
		identv, parentIdentOk := cr.Parent().(*ast.ValueSpec)
		callv, parentCallExprOk := cr.Parent().(*ast.CallExpr)

		isConst := false
		astutil.Apply(fileAst, func(cr *astutil.Cursor) bool {
			if (cr.Node() == identv) || (cr.Node() == assignv) || (cr.Node() == callv) {
				gendec, ok := cr.Parent().(*ast.GenDecl)
				if !ok {
					return true
				}
				isConst = gendec.Tok == token.CONST
				return false
			}
			return true
		}, nil)

		if (parentAssignOk || parentIdentOk || parentCallExprOk) && !isConst {
			cr.Replace(&ast.CallExpr{
				Fun:  ast.NewIdent("AES_DECRYPT"),
				Args: []ast.Expr{cn},
			})
		}

		return true
	}, nil)
}

func nencryptstring(pkgName string, fileAst *ast.File, key, nonce string) {
	astutil.Apply(fileAst, func(cr *astutil.Cursor) bool {
		cn, ok := cr.Node().(*ast.BasicLit)
		if !ok {
			return true
		}

		if cn.Kind != token.STRING {
			return true
		}

		assignv, parentAssign := cr.Parent().(*ast.AssignStmt)
		identv, parentIdent := cr.Parent().(*ast.ValueSpec)
		callv, parentCallExpr := cr.Parent().(*ast.CallExpr)

		isConst := false
		astutil.Apply(fileAst, func(cr *astutil.Cursor) bool {
			if (cr.Node() == identv) || (cr.Node() == assignv) || (cr.Node() == callv) {
				gendec, ok := cr.Parent().(*ast.GenDecl)
				if !ok {
					return true
				}
				isConst = gendec.Tok == token.CONST
				return false
			}
			return true
		}, nil)

		if (parentAssign || parentIdent || parentCallExpr) && !isConst {
			if *verbose {
				log.Printf("Enc:Assign : %#v, Current : %#v Parent : %#v\n", cn, cr.Node(), cr.Parent())
			}
			valInterpreted, err := strconv.Unquote(cn.Value)
			if err != nil {
				panic(err)
			}
			cr.Replace(&ast.BasicLit{
				Value: fmt.Sprintf("\"%s\"", stringencrypt(valInterpreted, key, nonce)),
				Kind:  token.STRING,
			})
		}

		return true
	}, nil)
}

func stringencrypt(plaintext string, keyHex, nonceHex string) string {
	key, _ := hex.DecodeString(keyHex)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	nonce, _ := hex.DecodeString(nonceHex)
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, []byte(plaintext), nil)
	return fmt.Sprintf("%x", ciphertext)
}